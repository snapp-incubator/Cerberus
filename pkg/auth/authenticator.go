package auth

import (
	"context"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/asaskevich/govalidator"
	"github.com/go-logr/logr"
	cerberusv1alpha1 "github.com/snapp-incubator/Cerberus/api/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "k8s.io/api/core/v1"
)

// Authenticator can generate cache from Kubernetes API server
// and it implements envoy.CheckRequest interface
type Authenticator struct {
	logger     logr.Logger
	httpClient *http.Client

	accessCache   *AccessCache
	servicesCache *ServicesCache

	cacheLock  sync.RWMutex
	updateLock sync.Mutex
}

// ExtraHeaders are headers which will be added to the response
type ExtraHeaders map[string]string

// AccessCache is where Authenticator holds its authentication data,
// under the hood it is a Map from RawTokens to some information about
// AccessToken, see AccessCacheEntry for more information
type AccessCache map[string]AccessCacheEntry

// ServicesCache will hold information about all listed and suppoerted
// Webservices by the Authenticator
type ServicesCache map[string]ServicesCacheEntry

// AccessCacheEntry will hold all datas included in AccessToken manifest,
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
	// does not contain Lookup information in its manifest
	CerberusReasonLookupIdentifierEmpty CerberusReason = "lookup-identifier-empty"

	// CerberusReasonBadDomainList means that domain list items are not in valid patterns
	CerberusReasonBadDomainList CerberusReason = "bad-domain-list"

	// CerberusReasonBadIpList means that ip list items are not in valid patterns which is CIDR notation of the networks
	CerberusReasonBadIpList CerberusReason = "bad-ip-list"

	// CerberusReasonDomainNotAllowed means that the given domain list
	//doesn't match with the allowed domain list for specific webservice
	CerberusReasonDomainNotAllowed CerberusReason = "domain-not-allowed"

	// CerberusReasonIpNotAllowed means that the given ip list
	//doesn't match with the ip domain list for specific webservice
	CerberusReasonIpNotAllowed CerberusReason = "ip-not-allowed"

	// CerberusReasonTokenNotFound means that given AccessToken is read
	// from request headers, but it is not listed by the Cerberus
	CerberusReasonTokenNotFound CerberusReason = "token-not-found"

	// CerberusReasonWebserviceNotFound means that given webservice in
	// the request context is not listed by Cerberus
	CerberusReasonWebserviceNotFound CerberusReason = "webservice-notfound"

	// CerberusReasonInvalidUpstreamAddress means that requested webservice
	// has an invalid upstream address in it's manifest
	CerberusReasonInvalidUpstreamAddress CerberusReason = "invalid-auth-upstream"

	// CerberusReasonSourceAuthTokenEmpty means that requested webservice
	// does not contain source upstream auth lookup header in it's manifest
	CerberusReasonSourceAuthTokenEmpty CerberusReason = "upstream-source-identifier-empty"

	// CerberusReasonTargetAuthTokenEmpty means that requested webservice
	// does not contain a target upstream auth lookup header in it's manifest
	CerberusReasonTargetAuthTokenEmpty CerberusReason = "upstream-target-identifier-empty"

	// CerberusReasonUpstreamAuthFailed means that the request to the specified
	// upstream failed due to an unidentified issue
	CerberusReasonUpstreamAuthFailed CerberusReason = "upstream-auth-failed"
)

//+kubebuilder:rbac:groups=cerberus.snappcloud.io,resources=accesstokens,verbs=get;list;watch;
//+kubebuilder:rbac:groups=cerberus.snappcloud.io,resources=accesstokens/status,verbs=get;
//+kubebuilder:rbac:groups=cerberus.snappcloud.io,resources=webservices,verbs=get;list;watch;
//+kubebuilder:rbac:groups=cerberus.snappcloud.io,resources=webservices/status,verbs=get;
//+kubebuilder:rbac:groups=cerberus.snappcloud.io,resources=webserviceaccountbindings,verbs=get;list;watch;
//+kubebuilder:rbac:groups=cerberus.snappcloud.io,resources=webserviceaccountbindings/status,verbs=get;
//+kubebuilder:rbac:groups="",namespace='cerberus-operator-system',resources=secrets,verbs=get;list;watch;create;update;patch;delete

// UpdateCache will accuire a lock on other UpdateCaches and will start to recreate
// the entire AccessCache and WebserviceCaches (which contains all authentication information)
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
	listOpts := &client.ListOptions{Namespace: "cerberus-operator-system"}

	t = time.Now()
	// TODO find cleaner way to select
	err = c.List(ctx, secrets,
		// client.MatchingLabels{"cerberus.snappcloud.io/secret": "true"},
		listOpts,
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
		if t, ok := secretValues[t.Namespace+"."+t.Name]; ok {
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
// has access to given Webservice (identified by its name) and returns proper CerberusReason
func (a *Authenticator) TestAccess(request *Request, wsvc ServicesCacheEntry) (bool, CerberusReason, ExtraHeaders) {
	newExtraHeaders := make(ExtraHeaders)
	ok, reason, token := a.readToken(request, wsvc)
	if !ok {
		return false, reason, newExtraHeaders
	}

	a.cacheLock.RLock()
	cacheReaders.Inc()
	defer a.cacheLock.RUnlock()
	defer cacheReaders.Dec()

	// Retrieve "x-forwarded-for" and "referrer" headers from the request
	xForwardedFor := request.Request.Header.Get("x-forwarded-for")
	referrer := request.Request.Header.Get("referrer")

	if token == "" {
		return false, CerberusReasonTokenEmpty, newExtraHeaders
	}

	ac, ok := (*a.accessCache)[token]

	if !ok {
		return false, CerberusReasonTokenNotFound, newExtraHeaders
	}

	// Check x-forwarded-for header against IP allow list
	if len(ac.Spec.IpAllowList) > 0 && xForwardedFor != "" {
		ipAllowed, err := CheckIP(xForwardedFor, ac.Spec.IpAllowList)
		if err != nil {
			return false, CerberusReasonBadIpList, newExtraHeaders
		}
		if !ipAllowed {
			return false, CerberusReasonIpNotAllowed, newExtraHeaders
		}
	}

	// Check referrer header against domain allow list
	if len(ac.Spec.DomainAllowList) > 0 && referrer != "" {
		domainAllowed, err := CheckDomain(referrer, ac.Spec.DomainAllowList)
		if err != nil {
			return false, CerberusReasonBadDomainList, newExtraHeaders
		}
		if !domainAllowed {
			return false, CerberusReasonDomainNotAllowed, newExtraHeaders
		}
	}

	newExtraHeaders["X-Cerberus-AccessToken"] = ac.ObjectMeta.Name

	if _, ok := (*a.accessCache)[token].allowedServices[wsvc.Name]; !ok {
		return false, CerberusReasonUnauthorized, newExtraHeaders
	}
	return true, CerberusReasonOK, newExtraHeaders
}

// readToken reads token from given Request object and
// will return error if it not exists at expected header
func (a *Authenticator) readToken(request *Request, wsvc ServicesCacheEntry) (bool, CerberusReason, string) {
	if wsvc.Spec.LookupHeader == "" {
		return false, CerberusReasonLookupIdentifierEmpty, ""
	}
	token := request.Request.Header.Get(wsvc.Spec.LookupHeader)
	return true, "", token
}

// readService reads requested webservice from cache and
// will return error if the object would not be found in cache
func (a *Authenticator) readService(wsvc string) (bool, CerberusReason, ServicesCacheEntry) {
	a.cacheLock.RLock()
	cacheReaders.Inc()
	defer a.cacheLock.RUnlock()
	defer cacheReaders.Dec()

	if wsvc == "" {
		return false, CerberusReasonLookupEmpty, ServicesCacheEntry{}
	}

	res, ok := (*a.servicesCache)[wsvc]
	if !ok {
		return false, CerberusReasonWebserviceNotFound, ServicesCacheEntry{}
	}
	return true, "", res
}

// Check is the function which is used to Authenticate and Respond to gRPC envoy.CheckRequest
func (a *Authenticator) Check(ctx context.Context, request *Request) (*Response, error) {

	wsvc := request.Context["webservice"]
	var extraHeaders ExtraHeaders
	var httpStatusCode int

	ok, reason, wsvcCacheEntry := a.readService(wsvc)
	if ok {
		ok, reason, extraHeaders = a.TestAccess(request, wsvcCacheEntry)
		if ok && hasUpstreamAuth(wsvcCacheEntry) {
			ok, reason = a.checkServiceUpstreamAuth(wsvcCacheEntry, request, &extraHeaders)
		}
	}

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

	return &Response{
		Allow:    ok,
		Response: response,
	}, nil
}

// NewAuthenticator creates new Authenticator object with given logger.
// currently it's not returning any error
func NewAuthenticator(logger logr.Logger) (*Authenticator, error) {
	a := Authenticator{
		logger:     logger,
		httpClient: &http.Client{},
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

// checkServiceUpstreamAuth function is designed to validate the request through
// the upstream authentication for a given webservice
func (a *Authenticator) checkServiceUpstreamAuth(service ServicesCacheEntry, request *Request, extraHeaders *ExtraHeaders) (bool, CerberusReason) {
	serviceUpstreamAuthCalls.Inc()

	if service.Spec.UpstreamHttpAuth.ReadTokenFrom == "" {
		return false, CerberusReasonSourceAuthTokenEmpty
	}
	if service.Spec.UpstreamHttpAuth.WriteTokenTo == "" {
		return false, CerberusReasonTargetAuthTokenEmpty
	}
	if !govalidator.IsRequestURL(service.Spec.UpstreamHttpAuth.Address) {
		return false, CerberusReasonInvalidUpstreamAddress
	}

	token := request.Request.Header.Get(service.Spec.UpstreamHttpAuth.ReadTokenFrom)

	// TODO: get http method from webservice crd
	req, err := http.NewRequest("GET", service.Spec.UpstreamHttpAuth.Address, nil)
	if err != nil {
		return false, CerberusReasonUpstreamAuthFailed
	}

	req.Header = http.Header{
		service.Spec.UpstreamHttpAuth.WriteTokenTo: {token},
		"Content-Type": {"application/json"},
	}

	a.httpClient.Timeout = time.Duration(service.Spec.UpstreamHttpAuth.Timeout) * time.Millisecond
	reqStart := time.Now()
	resp, err := a.httpClient.Do(req)
	reqDuration := time.Since(reqStart)
	if err != nil {
		return false, CerberusReasonUpstreamAuthFailed
	}

	labels := StatusLabel(resp.StatusCode)
	upstreamAuthRequestDuration.With(labels).Observe(reqDuration.Seconds())

	if resp.StatusCode != http.StatusOK {
		return false, CerberusReasonUnauthorized
	}
	// add requested careHeaders to extraHeaders for response
	for header, values := range resp.Header {
		for _, careHeader := range service.Spec.UpstreamHttpAuth.CareHeaders {
			if header == careHeader {
				if len(values) > 0 {
					(*extraHeaders)[header] = values[0]
				}
				break
			}
		}
	}

	return true, CerberusReasonOK
}

// hasUpstreamAuth evaluates whether the provided webservice
// upstreamauth instance is considered empty or not
func hasUpstreamAuth(service ServicesCacheEntry) bool {
	return service.Spec.UpstreamHttpAuth.Address != ""
}
