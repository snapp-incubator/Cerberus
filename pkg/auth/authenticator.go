package auth

import (
	"context"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/asaskevich/govalidator"
	"github.com/go-logr/logr"
	"github.com/snapp-incubator/Cerberus/api/v1alpha1"
	"github.com/snapp-incubator/Cerberus/internal/tracing"
	"go.opentelemetry.io/otel/attribute"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// downstreamDeadlineOffset sets an offset to downstream deadline inorder
// to save a little time to update metrics and answer downstream request
const downstreamDeadlineOffset = 50 * time.Microsecond

// Authenticator can generate cache from Kubernetes API server
// and it implements envoy.CheckRequest interface
type Authenticator struct {
	logger     logr.Logger
	httpClient *http.Client

	accessTokensCache *AccessTokensCache
	webservicesCache  *WebservicesCache

	cacheLock  sync.RWMutex
	updateLock sync.Mutex

	validators []AuthenticationValidation
}

// ExtraHeaders are headers which will be added to the response
type ExtraHeaders map[string]string

// ExtraHeaders setting generally
const (
	CerberusHeaderReasonHeader string = "X-Cerberus-Reason"
	ExternalAuthHandlerHeader  string = "X-Auth-Handler"
)

// CerberusHeaderName is the type which is used to identifies header name
type CerberusHeaderName string

// CerberusExtraHeaders are headers which will be added to the response starting
// with X-Cerberus-* this headers also will be set Test function
type CerberusExtraHeaders map[CerberusHeaderName]string

const (
	CerberusHeaderAccessLimitReason     CerberusHeaderName = "X-Cerberus-Access-Limit-Reason"
	CerberusHeaderTokenPriority         CerberusHeaderName = "X-Cerberus-Token-Priority"
	CerberusHeaderWebServiceMinPriority CerberusHeaderName = "X-Cerberus-Webservice-Min-Priority"
	CerberusHeaderAccessToken           CerberusHeaderName = "X-Cerberus-AccessToken"
)

// Access limit reasons
const (
	//TokenPriorityLowerThanServiceMinAccessLimit is the value to be set on CerberusHeaderAccessLimitReason
	// header when load-shedding is done due token priority values
	TokenPriorityLowerThanServiceMinAccessLimit string = "TokenPriorityLowerThanServiceMinimum"
)

// TestAccess will check if given AccessToken (identified by raw token in the request)
// has access to given Webservice (identified by its name) and returns proper CerberusReason
func (a *Authenticator) TestAccess(request *Request, wsvc WebservicesCacheEntry) (reason CerberusReason, newExtraHeaders CerberusExtraHeaders) {
	newExtraHeaders = make(CerberusExtraHeaders)
	reason, token := a.readToken(request, wsvc)
	if reason != "" {
		return
	}

	a.cacheLock.RLock()
	cacheReaders.Inc()
	defer a.cacheLock.RUnlock()
	defer cacheReaders.Dec()

	if token == "" {
		reason = CerberusReasonTokenEmpty
		return
	}

	ac, ok := a.accessTokensCache.ReadAccessToken(token)
	if !ok {
		reason = CerberusReasonTokenNotFound
		return
	}

	newExtraHeaders.set(CerberusHeaderAccessToken, ac.ObjectMeta.Name)

	for _, validator := range a.validators {
		var headers CerberusExtraHeaders
		reason, headers = validator.Validate(&ac, &wsvc, request)
		newExtraHeaders.merge(headers)
		if reason != "" {
			return
		}
	}
	return
}

// readToken reads token from given Request object and
// will return error if it not exists at expected header
func (a *Authenticator) readToken(request *Request, wsvc WebservicesCacheEntry) (CerberusReason, string) {
	if wsvc.Spec.LookupHeader == "" {
		return CerberusReasonLookupIdentifierEmpty, ""
	}
	token := request.Request.Header.Get(wsvc.Spec.LookupHeader)
	return "", token
}

// readService reads requested webservice from cache and
// will return error if the object would not be found in cache
func (a *Authenticator) readService(wsvc string) (CerberusReason, WebservicesCacheEntry) {
	a.cacheLock.RLock()
	cacheReaders.Inc()
	defer a.cacheLock.RUnlock()
	defer cacheReaders.Dec()

	res, ok := a.webservicesCache.ReadWebservice(wsvc)
	if !ok {
		return CerberusReasonWebserviceNotFound, WebservicesCacheEntry{}
	}
	return "", res
}

func toExtraHeaders(headers CerberusExtraHeaders) ExtraHeaders {
	extraHeaders := make(ExtraHeaders)
	for key, value := range headers {
		extraHeaders[string(key)] = value
	}
	return extraHeaders
}

// Check is the function which is used to Authenticate and Respond to gRPC envoy.CheckRequest
func (a *Authenticator) Check(ctx context.Context, request *Request) (*Response, error) {
	wsvc, ns, reason := readRequestContext(request)

	// generate opentelemetry span with given parameters
	ctx, span := tracing.StartSpan(ctx, "CheckFunction")
	defer func() {
		span.SetAttributes(
			attribute.String("cerberus-reason", string(reason)),
		)
		span.End()
	}()
	span.SetAttributes(
		attribute.String("webservice", wsvc),
		attribute.String("namespace", ns),
	)

	if reason != "" {
		return generateResponse(reason, nil), nil
	}
	wsvc = v1alpha1.WebserviceReference{
		Name:      wsvc,
		Namespace: ns,
	}.LocalName()

	request.Context[HasUpstreamAuth] = "false"
	var extraHeaders ExtraHeaders

	reason, wsvcCacheEntry := a.readService(wsvc)
	if reason == "" {
		var cerberusExtraHeaders CerberusExtraHeaders

		// perform TestAccess
		reason, cerberusExtraHeaders = a.TestAccess(request, wsvcCacheEntry)

		extraHeaders = toExtraHeaders(cerberusExtraHeaders)
		if reason == CerberusReasonOK && hasUpstreamAuth(wsvcCacheEntry) {
			request.Context[HasUpstreamAuth] = "true"
			reason = a.checkServiceUpstreamAuth(wsvcCacheEntry, request, &extraHeaders, ctx)
		}
	}

	var err error
	if reason == CerberusReasonUpstreamAuthTimeout || reason == CerberusReasonUpstreamAuthFailed {
		err = status.Error(codes.DeadlineExceeded, "Timeout exceeded")
	}

	return generateResponse(reason, extraHeaders), err
}

func readRequestContext(request *Request) (wsvc string, ns string, reason CerberusReason) {
	wsvc = request.Context["webservice"]
	if wsvc == "" {
		return "", "", CerberusReasonWebserviceEmpty
	}

	ns = request.Context["namespace"]
	if ns == "" {
		return "", "", CerberusReasonWebserviceNamespaceEmpty
	}

	return
}

// defineValidators creates a list of validations implemented.
// the validations will run along the order of the list.
func defineValidators() []AuthenticationValidation {
	return []AuthenticationValidation{
		&AuthenticatorPriorityValidation{},
		&AuthenticationIPValidation{},
		&AuthenticationDomainValidation{},
		&AuthenticationTokenAccessValidation{},
	}
}

// NewAuthenticator creates new Authenticator object with given logger.
// currently it's not returning any error
func NewAuthenticator(logger logr.Logger) *Authenticator {
	a := Authenticator{
		logger:     logger,
		httpClient: &http.Client{},
	}
	a.validators = defineValidators()
	return &a
}

// validateUpstreamAuthRequest validates the service before calling the upstream.
// when calling the upstream authentication, one of read or write tokens must be
// empty and the upstream address must be a valid url.
func validateUpstreamAuthRequest(service WebservicesCacheEntry) CerberusReason {
	if service.Spec.UpstreamHttpAuth.ReadTokenFrom == "" ||
		service.Spec.UpstreamHttpAuth.WriteTokenTo == "" {
		return CerberusReasonTargetAuthTokenEmpty
	}
	if !govalidator.IsRequestURL(service.Spec.UpstreamHttpAuth.Address) {
		return CerberusReasonInvalidUpstreamAddress
	}
	return ""
}

// setupUpstreamAuthRequest create request object to call upstream authentication
func setupUpstreamAuthRequest(upstreamHttpAuth *v1alpha1.UpstreamHttpAuthService, request *Request) (*http.Request, error) {
	token := request.Request.Header.Get(upstreamHttpAuth.ReadTokenFrom)
	req, err := http.NewRequest("GET", upstreamHttpAuth.Address, nil)
	if err != nil {
		return nil, err
	}
	req.Header = http.Header{
		upstreamHttpAuth.WriteTokenTo: {token},
		"Content-Type":                {"application/json"},
	}
	return req, nil
}

// adjustTimeout sets timeout value for httpClient.timeout
func (a *Authenticator) adjustTimeout(timeout int, downstreamDeadline time.Time, hasDownstreamDeadline bool) {
	a.httpClient.Timeout = time.Duration(timeout) * time.Millisecond
	if hasDownstreamDeadline {
		if time.Until(downstreamDeadline)-downstreamDeadlineOffset < a.httpClient.Timeout {
			a.httpClient.Timeout = time.Until(downstreamDeadline) - downstreamDeadlineOffset
		}
	}
}

// copyUpstreamHeaders copy a listing caring headers from upstream response to
// response headers
func copyUpstreamHeaders(resp *http.Response, extraHeaders *ExtraHeaders, careHeaders []string) {
	// Add requested careHeaders to extraHeaders for response
	for header, values := range resp.Header {
		for _, careHeader := range careHeaders {
			if header == careHeader && len(values) > 0 {
				(*extraHeaders)[header] = values[0]
				break
			}
		}
	}
}

// processResponseError handles upstream response headers and translates them to
// meaningful CerberusReason values
func processResponseError(err error) CerberusReason {
	if err == nil {
		return CerberusReasonNotSet
	}
	if urlErr, ok := err.(*url.Error); ok && urlErr != nil && urlErr.Timeout() {
		return CerberusReasonUpstreamAuthTimeout
	}
	return CerberusReasonUpstreamAuthFailed

}

// checkServiceUpstreamAuth function is designed to validate the request through
// the upstream authentication for a given webservice
func (a *Authenticator) checkServiceUpstreamAuth(service WebservicesCacheEntry, request *Request, extraHeaders *ExtraHeaders, ctx context.Context) (reason CerberusReason) {
	downstreamDeadline, hasDownstreamDeadline := ctx.Deadline()
	serviceUpstreamAuthCalls.With(AddWithDownstreamDeadline(nil, hasDownstreamDeadline)).Inc()

	_, span := tracing.StartSpan(ctx, "upstream-auth")
	defer func() {
		span.SetAttributes(
			attribute.String("upstream-auth-cerberus-reason", string(reason)),
		)
		span.End()
	}()
	span.SetAttributes(
		attribute.String("upstream-auth-address", service.Spec.UpstreamHttpAuth.Address),
	)

	if reason := validateUpstreamAuthRequest(service); reason != "" {
		return reason
	}
	upstreamAuth := service.Spec.UpstreamHttpAuth
	req, err := setupUpstreamAuthRequest(&upstreamAuth, request)
	if err != nil {
		return CerberusReasonUpstreamAuthNoReq
	}
	a.adjustTimeout(upstreamAuth.Timeout, downstreamDeadline, hasDownstreamDeadline)

	reqStart := time.Now()
	resp, err := a.httpClient.Do(req)
	reqDuration := time.Since(reqStart)

	if reason := processResponseError(err); reason != "" {
		return reason
	}

	labels := AddWithDownstreamDeadline(AddStatusLabel(nil, resp.StatusCode), hasDownstreamDeadline)
	upstreamAuthRequestDuration.With(labels).Observe(reqDuration.Seconds())

	span.SetAttributes(
		attribute.Float64("upstream-auth-rtt-seconds", reqDuration.Seconds()),
		attribute.Int("upstream-auth-status-code", resp.StatusCode),
	)

	if resp.StatusCode != http.StatusOK {
		return CerberusReasonUnauthorized
	}
	// add requested careHeaders to extraHeaders for response
	copyUpstreamHeaders(resp, extraHeaders, service.Spec.UpstreamHttpAuth.CareHeaders)
	return ""
}

// hasUpstreamAuth evaluates whether the provided webservice
// upstreamauth instance is considered empty or not
func hasUpstreamAuth(service WebservicesCacheEntry) bool {
	return service.Spec.UpstreamHttpAuth.Address != ""
}

// generateResponse initializes defaults for cerberus http result and creates a
// valid response from cerberus reasons and computed headers to inform the client
// that it has the access or not.
func generateResponse(reason CerberusReason, extraHeaders ExtraHeaders) *Response {
	ok := (reason == "")

	var httpStatusCode int
	if ok {
		httpStatusCode = http.StatusOK
		reason = CerberusReasonOK
	} else {
		httpStatusCode = http.StatusUnauthorized
	}

	response := http.Response{
		StatusCode: httpStatusCode,
		Header: http.Header{
			ExternalAuthHandlerHeader:  {"cerberus"},
			CerberusHeaderReasonHeader: {string(reason)},
		},
	}

	for key, value := range extraHeaders {
		response.Header.Add(string(key), value)
	}

	return &Response{
		Allow:    ok,
		Response: response,
	}
}

// merge merges 2 CerberusExtraHeaders and replaces if a key was present before
// with the new value in argument map
func (ch CerberusExtraHeaders) merge(h CerberusExtraHeaders) {
	for key, value := range h {
		ch[key] = value
	}
}

// set sets the values in CerberusExtraHeaders
// (creates if it's absent and update if it's present)
func (ch CerberusExtraHeaders) set(key CerberusHeaderName, value string) {
	ch[key] = value
}
