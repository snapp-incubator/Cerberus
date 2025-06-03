package auth

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/asaskevich/govalidator"
	"github.com/go-logr/logr"
	"github.com/snapp-incubator/Cerberus/api/v1alpha1"
	"github.com/snapp-incubator/Cerberus/internal/tracing"
	"go.opentelemetry.io/otel/attribute"
	otelcodes "go.opentelemetry.io/otel/codes"
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
	CerberusHeaderWebservice            CerberusHeaderName = "X-Cerberus-Webservice"
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
		if wsvc.defaultAccessToken == NoDefaultAccessToken {
			reason = CerberusReasonTokenEmpty
			return
		}
		token = wsvc.defaultAccessToken
	}

	ac, ok := a.accessTokensCache.ReadAccessToken(token)
	if !ok {
		reason = CerberusReasonTokenNotFound
		return
	}

	newExtraHeaders.set(CerberusHeaderAccessToken, ac.LocalName())
	newExtraHeaders.set(CerberusHeaderWebservice, wsvc.LocalName())

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
func (a *Authenticator) Check(ctx context.Context, request *Request) (finalResponse *Response, err error) {
	start_time := time.Now()
	wsvc, ns, reason := readRequestContext(request)

	// generate opentelemetry span with given parameters
	parentCtx := tracing.ReadParentSpanFromRequest(ctx, request.Request)
	ctx, span := tracing.StartSpan(parentCtx, "CheckFunction",
		attribute.String("webservice", wsvc),
		attribute.String("namespace", ns),
	)
	defer func() {
		extraAttrs := []attribute.KeyValue{
			attribute.String("cerberus-reason", string(reason)),
		}
		if finalResponse != nil {
			extraAttrs = append(extraAttrs,
				attribute.Bool("final-response-ok", finalResponse.Allow),
			)
			for k, v := range finalResponse.Response.Header {
				extraAttrs = append(extraAttrs,
					attribute.String("final-extra-headers-"+k, strings.Join(v, ",")),
				)
			}
		}
		tracing.EndSpan(span, start_time, extraAttrs...)
	}()

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
		if reason == "" && hasUpstreamAuth(wsvcCacheEntry) {
			request.Context[HasUpstreamAuth] = "true"
			reason = a.checkServiceUpstreamAuth(wsvcCacheEntry, request, &extraHeaders, ctx)
		}
	}

	if reason == CerberusReasonUpstreamAuthTimeout || reason == CerberusReasonUpstreamAuthFailed {
		err = status.Error(codes.DeadlineExceeded, "Timeout exceeded")
	}

	finalResponse = generateResponse(reason, extraHeaders)
	return
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

// validateUpstreamAuthRequest validates a single upstream service configuration.
// ReadTokenFrom and WriteTokenTo must not be empty, and the address must be a valid URL.
func validateUpstreamAuthRequest(upstreamAuth v1alpha1.UpstreamHttpAuthService) CerberusReason {
	if upstreamAuth.ReadTokenFrom == "" || upstreamAuth.WriteTokenTo == "" {
		return CerberusReasonTargetAuthTokenEmpty
	}
	if !govalidator.IsRequestURL(upstreamAuth.Address) {
		return CerberusReasonInvalidUpstreamAddress
	}
	return ""
}

// setupUpstreamAuthRequest creates a request object to call an upstream authentication service.
// It uses the provided currentUpstreamToken and forwards specified headers from the previous response.
func setupUpstreamAuthRequest(upstreamHttpAuth *v1alpha1.UpstreamHttpAuthService, currentUpstreamToken string, forwardedHeaders http.Header) (*http.Request, error) {
	req, err := http.NewRequest("GET", upstreamHttpAuth.Address, nil)
	if err != nil {
		return nil, err
	}
	req.Header = forwardedHeaders // Start with headers to forward

	// Ensure Content-Type and the auth token header are set correctly.
	// If forwardedHeaders already contains WriteTokenTo or Content-Type, they will be overwritten here,
	// which is generally the desired behavior as these are specific to this request.
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	req.Header.Set(upstreamHttpAuth.WriteTokenTo, currentUpstreamToken)
	req.Header.Set("Content-Type", "application/json")

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
// a chain of upstream authentication services for a given webservice.
func (a *Authenticator) checkServiceUpstreamAuth(serviceCacheEntry WebservicesCacheEntry, origRequest *Request, extraHeaders *ExtraHeaders, ctx context.Context) (reason CerberusReason) {
	overallStartTime := time.Now()
	downstreamDeadline, hasDownstreamDeadline := ctx.Deadline()
	serviceUpstreamAuthCalls.With(AddWithDownstreamDeadlineLabel(nil, hasDownstreamDeadline)).Inc()

	// accumulatedCareHeaders will store all CareHeaders from all successful upstream responses
	accumulatedCareHeaders := make(http.Header)
	// currentRequestToken holds the token to be sent to the current upstream service
	var currentRequestToken string
	// headersToForward holds CareHeaders from the *previous* successful response to be sent to the *current* request
	headersToForward := make(http.Header)

	var upstreamServicesToProcess []v1alpha1.UpstreamHttpAuthService

	if len(serviceCacheEntry.Spec.UpstreamHttpAuths) > 0 {
		upstreamServicesToProcess = serviceCacheEntry.Spec.UpstreamHttpAuths
		if serviceCacheEntry.Spec.UpstreamHttpAuth.Address != "" {
			a.logger.Info("Both UpstreamHttpAuths and deprecated UpstreamHttpAuth are set. UpstreamHttpAuths will take precedence.", "webservice", serviceCacheEntry.LocalName())
		}
	} else if serviceCacheEntry.Spec.UpstreamHttpAuth.Address != "" {
		upstreamServicesToProcess = []v1alpha1.UpstreamHttpAuthService{serviceCacheEntry.Spec.UpstreamHttpAuth}
	} else {
		// No upstream services configured, so authentication is considered successful at this stage.
		return CerberusReasonNotSet
	}

	// Initial token read from the original client request, based on the *first* upstream's config.
	if len(upstreamServicesToProcess) > 0 {
		firstUpstream := upstreamServicesToProcess[0]
		if firstUpstream.ReadTokenFrom != "" {
			currentRequestToken = origRequest.Request.Header.Get(firstUpstream.ReadTokenFrom)
		}
	}

	for i, upstreamAuthService := range upstreamServicesToProcess {
		loopIterationStartTime := time.Now()
		parentCtxForLoopIteration := ctx
		if i > 0 { // For subsequent requests, the parent span is the previous upstream call
			// This logic might need refinement if spans aren't nested as expected.
			// For now, each upstream call is a child of the main checkServiceUpstreamAuth span.
		}

		iterationSpanCtx, iterationSpan := tracing.StartSpan(parentCtxForLoopIteration, "cerberus-upstream-auth-iteration",
			attribute.String("upstream-auth-address", upstreamAuthService.Address),
			attribute.Int("upstream-auth-index", i),
		)
		defer tracing.EndSpan(iterationSpan, loopIterationStartTime, attribute.String("cerberus-reason", string(reason)))

		if reason = validateUpstreamAuthRequest(upstreamAuthService); reason != "" {
			iterationSpan.SetStatus(otelcodes.Error, "validation failed")
			return reason // Validation failure for this specific upstream service
		}

		// Prepare the request for the current upstream service
		req, err := setupUpstreamAuthRequest(&upstreamAuthService, currentRequestToken, headersToForward)
		if err != nil {
			iterationSpan.RecordError(err)
			iterationSpan.SetStatus(otelcodes.Error, "failed to setup upstream request")
			return CerberusReasonUpstreamAuthNoReq // Failed to create the request object
		}
		req = req.WithContext(iterationSpanCtx) // Propagate tracing context

		a.adjustTimeout(upstreamAuthService.Timeout, downstreamDeadline, hasDownstreamDeadline)

		reqStartTime := time.Now()
		resp, err := a.httpClient.Do(req)
		reqDuration := time.Since(reqStartTime)

		iterationSpan.SetAttributes(
			attribute.String("upstream-http-request-start", reqStartTime.Format(tracing.TimeFormat)),
			attribute.String("upstream-http-request-end", time.Now().Format(tracing.TimeFormat)),
			attribute.Float64("upstream-http-request-rtt-seconds", reqDuration.Seconds()),
		)

		if resp != nil {
			iterationSpan.SetAttributes(attribute.Int("upstream-auth-status-code", resp.StatusCode))
			labels := AddWithDownstreamDeadlineLabel(AddStatusLabel(nil, resp.StatusCode), hasDownstreamDeadline)
			upstreamAuthRequestDuration.With(labels).Observe(reqDuration.Seconds())
		} else {
			labels := AddWithDownstreamDeadlineLabel(nil, hasDownstreamDeadline)
			upstreamAuthFailedRequests.With(labels).Inc()
		}

		if reason = processResponseError(err); reason != "" {
			iterationSpan.RecordError(err)
			iterationSpan.SetStatus(otelcodes.Error, "upstream auth http request failed")
			return reason // HTTP call error (e.g., timeout, network issue)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			iterationSpan.SetStatus(otelcodes.Error, "upstream auth returned non-OK status")
			return CerberusReasonUnauthorized // Non-200 status from upstream
		}

		// Successful authentication from this upstream service
		iterationSpan.SetStatus(otelcodes.Ok, "upstream auth successful")

		// Clear headersToForward for the next iteration, then populate with current response's CareHeaders
		headersToForward = make(http.Header)
		for _, careHeaderName := range upstreamAuthService.CareHeaders {
			if values := resp.Header.Values(careHeaderName); len(values) > 0 {
				// Forward all values for the care header
				for _, value := range values {
					headersToForward.Add(careHeaderName, value)
					// Also accumulate for the final downstream response
                                        // Use .Add to handle multi-value headers correctly for extraHeaders
                                        if _, ok := (*extraHeaders)[careHeaderName]; !ok {
                                            (*extraHeaders)[careHeaderName] = values[0] // For single string map
                                        } else {
                                             // This part is tricky with ExtraHeaders map[string]string.
                                             // For now, just appending to existing if already there, separated by comma.
                                             // A better solution might be to change ExtraHeaders type.
                                            (*extraHeaders)[careHeaderName] += "," + values[0]
                                        }

                                        // Accumulate for actual downstream response headers (supports multi-value)
                                        accumulatedCareHeaders.Add(careHeaderName, value)
				}
			}
		}

		// Update token for the *next* upstream request, if configured
		if upstreamAuthService.ReadTokenFrom != "" {
			if newToken := resp.Header.Get(upstreamAuthService.ReadTokenFrom); newToken != "" {
				currentRequestToken = newToken
				iterationSpan.SetAttributes(attribute.Bool("token-propagated-to-next-upstream", true))
			} else {
				iterationSpan.SetAttributes(attribute.Bool("token-propagated-to-next-upstream", false))
				// Token for next request remains unchanged if not found in current response
			}
		}
	}

	// If loop completes, all upstreams authenticated successfully.
	// The accumulatedCareHeaders are already added to *extraHeaders.
	// We need to make sure *extraHeaders correctly reflects multi-value headers.
	// The current logic for *extraHeaders (map[string]string) is problematic for multi-value.
	// Let's rebuild *extraHeaders from accumulatedCareHeaders (http.Header) to handle this better.
	// Clear existing extraHeaders that might have been partially populated
	for k := range *extraHeaders {
		delete(*extraHeaders, k)
	}
	for key, values := range accumulatedCareHeaders {
		if len(values) > 0 {
			(*extraHeaders)[key] = strings.Join(values, ",") // Join multiple values if any
		}
	}


	tracing.EndSpan(nil, overallStartTime) // End the main span for checkServiceUpstreamAuth
	return CerberusReasonNotSet // "" indicates success
}

// hasUpstreamAuth evaluates whether the provided webservice
// has any upstream authentication services configured, checking new and deprecated fields.
func hasUpstreamAuth(service WebservicesCacheEntry) bool {
	if len(service.Spec.UpstreamHttpAuths) > 0 {
		return true
	}
	if service.Spec.UpstreamHttpAuth.Address != "" {
		return true
	}
	return false
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
