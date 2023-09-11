package auth

import (
	"context"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
	cerberusv1alpha1 "github.com/snapp-incubator/Cerberus/api/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "k8s.io/api/core/v1"
)

// Authenticator can generate cache from Kubernetes API server
// and it implements envoy.CheckRequest interface
type Authenticator struct {
	logger logr.Logger

	accessCache   *AccessCache
	servicesCache *ServicesCache

	cacheLock  sync.RWMutex
	updateLock sync.Mutex
}

// ExtraHeaders are headers which will be added to the response
type ExtraHeaders map[string]string

// AccessCache is where Authenticator holds it's authentication data,
// under the hood it is a Map from RawTokens to some informations about
// AccessToken, see AccessCacheEntry for more informations
type AccessCache map[string]AccessCacheEntry

// ServicesCache will hold informations about all listed and suppoerted
// Webservices by the Authenticator
type ServicesCache map[string]ServicesCacheEntry

// AccessCacheEntry will hold all datas included in AccessToken manifest
// and it also holds a map[string]struct{} which holds name of Webservices
// which the given token has access to.
type AccessCacheEntry struct {
	cerberusv1alpha1.AccessToken
	// limiter Limiter
	allowedServices map[string]struct{}
}

// ServicesCacheEntry will hold all datas included in Webservice manifest
type ServicesCacheEntry struct {
	cerberusv1alpha1.WebService
}

// CerberusReason is the type which is used to identfies the reason
// that caused Cerberus to accept/reject the request.
type CerberusReason string

const (
	// CerberusReasonOK means that Cerberus finds no error in the request
	// and the request is Authenticated for next actions. All CerberusReasons
	// OTHER THAN CerberusReasonOK means that the request is NOT authenticated
	CerberusReasonOK CerberusReason = "ok"

	// CerberusReasonUnauthorized means that given AccessToken is found but
	// it does NOT have access to requested Webservice
	CerberusReasonUnauthorized CerberusReason = "unauthorized"

	// CerberusReasonTokenEmpty means that the lookupHeader which is defined
	// by requested Webservice is empty in the request
	CerberusReasonTokenEmpty CerberusReason = "token-empty"

	// CerberusReasonLookupEmpty means that Webservice is empty in the
	// provided request context
	CerberusReasonLookupEmpty CerberusReason = "lookup-empty"

	// CerberusReasonLookupIdentifierEmpty means that requested webservice
	// does not contain Lookup information in it's manifest
	CerberusReasonLookupIdentifierEmpty CerberusReason = "lookup-identifier-empty"

	// CerberusReasonTokenNotFound means that given AccessToken is read
	// from request headers but it is not listed by the Cerberus
	CerberusReasonTokenNotFound CerberusReason = "token-notfound"

	// CerberusReasonWebserviceNotFound means that given webservice in
	// the request context is not listed by Cerberus
	CerberusReasonWebserviceNotFound CerberusReason = "webservice-notfound"
)

//+kubebuilder:rbac:groups=cerberus.snappcloud.io,resources=accesstokens,verbs=get;list;watch;
//+kubebuilder:rbac:groups=cerberus.snappcloud.io,resources=accesstokens/status,verbs=get;
//+kubebuilder:rbac:groups=cerberus.snappcloud.io,resources=webservices,verbs=get;list;watch;
//+kubebuilder:rbac:groups=cerberus.snappcloud.io,resources=webservices/status,verbs=get;
//+kubebuilder:rbac:groups=cerberus.snappcloud.io,resources=webserviceaccountbindings,verbs=get;list;watch;
//+kubebuilder:rbac:groups=cerberus.snappcloud.io,resources=webserviceaccountbindings/status,verbs=get;
//+kubebuilder:rbac:groups="",namespace='cerberus-operator-system',resources=secrets,verbs=get;list;watch;create;update;patch;delete

// UpdateCache will accuire a lock on other UpdateCaches and will start to recreate
// the entire AccessCache and WebserviceCaches (which contains all authentication informations)
func (a *Authenticator) UpdateCache(c client.Client, ctx context.Context, readOnly bool) error {
	cacheUpdateCount.Inc()
	cacheUpdateStartTime := time.Now()
	defer func() {
		cacheUpdateLatency.Observe(time.Since(cacheUpdateStartTime).Seconds())
	}()

	a.updateLock.Lock()
	defer a.updateLock.Unlock()

	var err error
	tokens := &cerberusv1alpha1.AccessTokenList{}
	secrets := &v1.SecretList{}
	bindings := &cerberusv1alpha1.WebserviceAccessBindingList{}
	webservices := &cerberusv1alpha1.WebServiceList{}

	t := time.Now()
	err = c.List(ctx, tokens)
	fetchObjectListLatency.With(KindLabel(MetricsKindAccessToken)).Observe(time.Since(t).Seconds())
	if err != nil {
		return err
	}

	t = time.Now()
	err = c.List(ctx, bindings)
	fetchObjectListLatency.With(KindLabel(MetricsKindWebserviceAccessBinding)).Observe(time.Since(t).Seconds())
	if err != nil {
		return err
	}

	t = time.Now()
	err = c.List(ctx, webservices)
	fetchObjectListLatency.With(KindLabel(MetricsKindWebservice)).Observe(time.Since(t).Seconds())
	if err != nil {
		return err
	}

	t = time.Now()
	// TODO find cleaner way to select
	err = c.List(ctx, secrets,
		client.MatchingLabels{"cerberus.snappcloud.io/secret": "true"},
		client.InNamespace("cerberus-operator-system"),
	)
	fetchObjectListLatency.With(KindLabel(MetricsKindSecret)).Observe(time.Since(t).Seconds())
	if err != nil {
		return err
	}

	// convert secret list to map for faster searchs
	secretValues := make(map[string]string)
	for _, secret := range secrets.Items {
		if t, ok := secret.Data["token"]; ok {
			secretValues[secret.Name] = string(t)
		}
	}

	accessTokenRawValue := func(t *cerberusv1alpha1.AccessToken) (string, bool) {
		if t, ok := secretValues[t.Spec.TokenSecretRef.Name]; ok {
			return t, ok
		}
		return "", false
	}

	newAccessCache := make(AccessCache)
	rawToken := make(map[string]string)
	for _, token := range tokens.Items {
		if t, ok := accessTokenRawValue(&token); ok {
			rawToken[token.Name] = t
			newAccessCache[t] = AccessCacheEntry{
				AccessToken:     token,
				allowedServices: make(map[string]struct{}),
			}
		}
	}
	accessCacheEntries.Set(float64(len(newAccessCache)))

	for _, binding := range bindings.Items {
		for _, subject := range binding.Spec.Subjects {
			for _, webservice := range binding.Spec.Webservices {
				if t, ok := rawToken[subject]; ok {
					newAccessCache[t].allowedServices[webservice] = struct{}{}
				}
			}
		}
	}

	newServicesCache := make(ServicesCache)
	for _, webservice := range webservices.Items {
		newServicesCache[webservice.Name] = ServicesCacheEntry{
			WebService: webservice,
		}
	}
	webserviceCacheEntries.Set(float64(len(newServicesCache)))

	// TODO: remove this line
	a.logger.Info("new access cache", "accessCache", newAccessCache, "servicesCache", newServicesCache)

	cacheWriteLockRequestStartTime := time.Now()
	a.cacheLock.Lock()
	cacheWriteLockWaitingTime.Observe(time.Since(cacheWriteLockRequestStartTime).Seconds())
	defer a.cacheLock.Unlock()

	cacheWriteStartTime := time.Now()
	a.accessCache = &newAccessCache
	a.servicesCache = &newServicesCache
	cacheWriteTime.Observe(time.Since(cacheWriteStartTime).Seconds())
	return nil
}

// TestAccess will check if given AccessToken (identified by raw token in the request)
// has access to given Webservice (identified by it's name) and returns proper CerberusReason
func (a *Authenticator) TestAccess(wsvc string, token string) (bool, CerberusReason, ExtraHeaders) {
	a.cacheLock.RLock()
	cacheReaders.Inc()
	defer a.cacheLock.RUnlock()
	defer cacheReaders.Dec()

	newExtraHeaders := make(ExtraHeaders)

	if wsvc == "" {
		return false, CerberusReasonLookupEmpty, newExtraHeaders
	}
	if token == "" {
		return false, CerberusReasonTokenEmpty, newExtraHeaders
	}

	if _, ok := (*a.servicesCache)[wsvc]; !ok {
		return false, CerberusReasonWebserviceNotFound, newExtraHeaders
	}

	ac, ok := (*a.accessCache)[token]

	if !ok {
		return false, CerberusReasonTokenNotFound, newExtraHeaders
	}

	newExtraHeaders["X-Cerberus-AccessToken"] = ac.AccessToken.ObjectMeta.Name

	if _, ok := (*a.accessCache)[token].allowedServices[wsvc]; !ok {
		return false, CerberusReasonUnauthorized, newExtraHeaders
	}

	return true, CerberusReasonOK, newExtraHeaders
}

// readToken reads token from given Request object and
// will return error if it not exists at expected header
func (a *Authenticator) readToken(request *Request) (bool, CerberusReason, string) {
	wsvc := request.Context["webservice"]
	res, ok := (*a.servicesCache)[wsvc]
	if !ok {
		return false, CerberusReasonWebserviceNotFound, ""
	}
	if res.Spec.LookupHeader == "" {
		return false, CerberusReasonLookupIdentifierEmpty, ""
	}
	token := request.Request.Header.Get(res.Spec.LookupHeader)
	return true, "", token
}

// Check is the function which is used to Authenticate and Respond to gRPC envoy.CheckRequest
func (a *Authenticator) Check(ctx context.Context, request *Request) (*Response, error) {
	reqStartTime := time.Now()
	wsvc := request.Context["webservice"]

	ok, reason, token := a.readToken(request)
	var extraHeaders ExtraHeaders
	var httpStatusCode int

	if ok {
		ok, reason, extraHeaders = a.TestAccess(wsvc, token)
	}

	// TODO: remove this line
	a.logger.Info("checking request", "reason", reason, "req", request)
	if ok {
		httpStatusCode = http.StatusOK
	} else {
		httpStatusCode = http.StatusUnauthorized
	}

	response := http.Response{
		StatusCode: httpStatusCode,
		Header: http.Header{
			"X-Auth-Handler":    {"cerberus"},
			"X-Cerberus-Reason": {string(reason)},
		},
	}

	for key, value := range extraHeaders {
		response.Header.Add(key, value)
	}

	// update metrics
	reqCount.With(ReasonLabel(reason)).Inc()
	reqLatency.With(ReasonLabel(reason)).Observe(time.Since(reqStartTime).Seconds())

	return &Response{
		Allow:    ok,
		Response: response,
	}, nil
}

// NewAuthenticator creates new Authenticator object with given logger.
// currently it's not returning any error
func NewAuthenticator(logger logr.Logger) (*Authenticator, error) {
	a := Authenticator{
		logger: logger,
	}
	return &a, nil
}

// CheckIP checks if given ip is a member of given CIDR networks or not
// ipAllowList should be CIDR notation of the networks or net.ParseError will be retuned
func CheckIP(ip string, ipAllowList []string) (bool, error) {
	clientIP := net.ParseIP(ip)

	for _, AllowedRangeIP := range ipAllowList {
		_, subnet, err := net.ParseCIDR(AllowedRangeIP)
		if err != nil {
			return false, err
		}

		if subnet.Contains(clientIP) {
			return true, nil
		}
	}
	return false, nil
}

// CheckDomain checks if given domain will match to one of the GLOB patterns in
// domainAllowedList (the list items should be valid patterns or ErrBadPattern will be returned)
func CheckDomain(domain string, domainAllowedList []string) (bool, error) {
	for _, pattern := range domainAllowedList {
		pattern = strings.ToLower(pattern)
		domain = strings.ToLower(domain)

		matched, err := filepath.Match(pattern, domain)
		if err != nil {
			return false, err
		}
		if matched {
			return true, nil
		}
	}
	return false, nil
}
