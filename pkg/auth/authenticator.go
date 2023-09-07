package auth

import (
	"context"
	"net"
	"net/http"
	"regexp"
	"sync"

	"github.com/asaskevich/govalidator"
	"github.com/go-logr/logr"
	cerberusv1alpha1 "github.com/snapp-incubator/Cerberus/api/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "k8s.io/api/core/v1"
)

type Authenticator struct {
	logger     logr.Logger
	httpClient *http.Client

	accessCache   *AccessCache
	servicesCache *ServicesCache

	cacheLock  sync.RWMutex
	updateLock sync.Mutex
}

type ExtraHeaders map[string]string
type AccessCache map[string]AccessCacheEntry
type ServicesCache map[string]ServicesCacheEntry

type AccessCacheEntry struct {
	cerberusv1alpha1.AccessToken
	// limiter Limiter
	allowedServices map[string]struct{}
}

type ServicesCacheEntry struct {
	cerberusv1alpha1.WebService
}

type CerberusReason string

const (
	CerberusReasonOK                     CerberusReason = "ok"
	CerberusReasonUnauthorized           CerberusReason = "unauthorized"
	CerberusReasonTokenEmpty             CerberusReason = "token-empty"
	CerberusReasonLookupEmpty            CerberusReason = "lookup-empty"
	CerberusReasonLookupIdentifierEmpty  CerberusReason = "lookup-identifier-empty"
	CerberusReasonTokenNotFound          CerberusReason = "token-notfound"
	CerberusReasonWebserviceNotFound     CerberusReason = "webservice-notfound"
	CerberusReasonInvalidUpstreamAddress CerberusReason = "invalid-auth-upstream"
	CerberusReasonSourceAuthTokenEmpty   CerberusReason = "upstream-source-identifier-empty"
	CerberusReasonTargetAuthTokenEmpty   CerberusReason = "upstream-target-identifier-empty"
	CerberusReasonUpstreamAuthFailed     CerberusReason = "upstream-auth-failed"
)

//+kubebuilder:rbac:groups=cerberus.snappcloud.io,resources=accesstokens,verbs=get;list;watch;
//+kubebuilder:rbac:groups=cerberus.snappcloud.io,resources=accesstokens/status,verbs=get;
//+kubebuilder:rbac:groups=cerberus.snappcloud.io,resources=webservices,verbs=get;list;watch;
//+kubebuilder:rbac:groups=cerberus.snappcloud.io,resources=webservices/status,verbs=get;
//+kubebuilder:rbac:groups=cerberus.snappcloud.io,resources=webserviceaccountbindings,verbs=get;list;watch;
//+kubebuilder:rbac:groups=cerberus.snappcloud.io,resources=webserviceaccountbindings/status,verbs=get;
//+kubebuilder:rbac:groups="",namespace='cerberus-operator-system',resources=secrets,verbs=get;list;watch;create;update;patch;delete

func (a *Authenticator) UpdateCache(c client.Client, ctx context.Context, readOnly bool) error {
	a.updateLock.Lock()
	defer a.updateLock.Unlock()

	var err error
	tokens := &cerberusv1alpha1.AccessTokenList{}
	secrets := &v1.SecretList{}
	bindings := &cerberusv1alpha1.WebserviceAccessBindingList{}
	webservices := &cerberusv1alpha1.WebServiceList{}

	err = c.List(ctx, tokens)
	if err != nil {
		return err
	}

	err = c.List(ctx, bindings)
	if err != nil {
		return err
	}

	err = c.List(ctx, webservices)
	if err != nil {
		return err
	}

	// TODO find cleaner way to select
	err = c.List(ctx, secrets,
		client.MatchingLabels{"cerberus.snappcloud.io/secret": "true"},
		client.InNamespace("cerberus-operator-system"),
	)
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

	a.logger.Info("new access cache", "accessCache", newAccessCache, "servicesCache", newServicesCache)

	a.cacheLock.Lock()
	defer a.cacheLock.Unlock()
	a.accessCache = &newAccessCache
	a.servicesCache = &newServicesCache
	return nil
}

func (a *Authenticator) TestAccess(wsvc string, token string) (bool, CerberusReason, ExtraHeaders) {
	a.cacheLock.RLock()
	defer a.cacheLock.RUnlock()

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

func (a *Authenticator) Check(ctx context.Context, request *Request) (*Response, error) {
	wsvc := request.Context["webservice"]

	ok, reason, token := a.readToken(request)
	var extraHeaders ExtraHeaders
	var httpStatusCode int

	if ok {
		ok, reason, extraHeaders = a.TestAccess(wsvc, token)
	}
	if ok {
		ok, reason = a.checkServiceUpstreamAuth(wsvc, request, &extraHeaders)
	}

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

	return &Response{
		Allow:    ok,
		Response: response,
	}, nil
}

func NewAuthenticator(logger logr.Logger) (*Authenticator, error) {
	a := Authenticator{
		logger:     logger,
		httpClient: &http.Client{},
	}
	return &a, nil
}

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

func CheckDomain(domain string, domainAllowedList []string) (bool, error) {
	for _, pattern := range domainAllowedList {
		matched, err := regexp.MatchString(pattern, domain)
		if err != nil {
			return false, err
		}
		if matched {
			return true, nil
		}
	}
	return false, nil
}

func (a *Authenticator) checkServiceUpstreamAuth(wsvc string, request *Request, extraHeaders *ExtraHeaders) (bool, CerberusReason) {
	service, ok := (*a.servicesCache)[wsvc]
	if !ok {
		return false, CerberusReasonWebserviceNotFound
	}
	if service.Spec.UpstreamHttpAuth == (cerberusv1alpha1.UpstreamHttpAuthService{}) {
		return true, CerberusReasonOK
	}
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

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return false, CerberusReasonUpstreamAuthFailed
	}
	if resp.StatusCode != http.StatusOK {
		return false, CerberusReasonUnauthorized
	}
	var headersString string
	for header, values := range resp.Header {
		for _, value := range values {
			headersString += header + ": " + value + "\n"
		}
	}
	(*extraHeaders)["X-Cerberus-Upstream-Headers"] = headersString

	return true, CerberusReasonOK
}
