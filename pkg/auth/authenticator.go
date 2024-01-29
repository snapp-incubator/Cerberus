package auth

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/asaskevich/govalidator"
	"github.com/go-logr/logr"
	"github.com/snapp-incubator/Cerberus/api/v1alpha1"
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

	// CerberusReasonInvalidSourceIp means that source ip in remoteAddre is not valid
	CerberusReasonInvalidSourceIp CerberusReason = "invalid-source-ip"

	// CerberusReasonEmptySourceIp means that source ip is empty
	CerberusReasonEmptySourceIp CerberusReason = "source-ip-empty"

	// CerberusReasonBadIpList means that ip list items are not in valid patterns which is CIDR notation of the networks
	CerberusReasonBadIpList CerberusReason = "bad-ip-list"

	// CerberusReasonDomainNotAllowed means that the given domain list
	//doesn't match with the allowed domain list for specific webservice
	CerberusReasonDomainNotAllowed CerberusReason = "domain-not-allowed"

	// CerberusReasonIpNotAllowed means that the given ip list
	//doesn't match with the ip domain list for specific webservice
	CerberusReasonIpNotAllowed CerberusReason = "ip-not-allowed"

	// CerberusReasonAccessLimited means that the token has a priority lower than the minimum required priority set by the web service
	CerberusReasonAccessLimited CerberusReason = "access-limited"

	// CerberusReasonTokenNotFound means that given AccessToken is read
	// from request headers, but it is not listed by the Cerberus
	CerberusReasonTokenNotFound CerberusReason = "token-not-found"

	// CerberusReasonWebserviceNotFound means that given webservice in
	// the request context is not listed by Cerberus
	CerberusReasonWebserviceNotFound CerberusReason = "webservice-notfound"

	// CerberusReasonWebserviceEmpty means that given webservice in
	// the request context is empty or it's not given at all
	CerberusReasonWebserviceEmpty CerberusReason = "webservice-empty"

	// CerberusReasonWebserviceNamespaceEmpty means that given namespace of webservice in
	// the request context is empty or it's not given at all
	CerberusReasonWebserviceNamespaceEmpty CerberusReason = "webservice-namespace-empty"

	// CerberusReasonInvalidUpstreamAddress means that requested webservice
	// has an invalid upstream address in it's manifest
	CerberusReasonInvalidUpstreamAddress CerberusReason = "invalid-auth-upstream"

	// CerberusReasonSourceAuthTokenEmpty means that requested webservice
	// does not contain source upstream auth lookup header in it's manifest
	CerberusReasonSourceAuthTokenEmpty CerberusReason = "upstream-source-identifier-empty"

	// CerberusReasonTargetAuthTokenEmpty means that requested webservice
	// does not contain a target upstream auth lookup header in it's manifest
	CerberusReasonTargetAuthTokenEmpty CerberusReason = "upstream-target-identifier-empty"

	// CerberusReasonUpstreamAuthTimeout means that the request to the specified
	// upstream timeout with respect to request deadline
	CerberusReasonUpstreamAuthTimeout CerberusReason = "upstream-auth-timeout"

	// CerberusReasonUpstreamAuthFailed means that the request to the specified
	// upstream failed due to an unidentified issue
	CerberusReasonUpstreamAuthFailed CerberusReason = "upstream-auth-failed"

	// CerberusReasonUpstreamAuthNoReq means that cerberus failed to create
	// request for specified upstream auth
	CerberusReasonUpstreamAuthNoReq CerberusReason = "upstream-auth-no-request"
)

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
		return
	}

	ac, ok := a.accessTokensCache.ReadAccesstoken(token)
	if !ok {
		return
	}

	newExtraHeaders.set(CerberusHeaderAccessToken, ac.ObjectMeta.Name)

	reason, h := a.testPriority(ac, wsvc)
	newExtraHeaders.merge(h)
	if reason != "" {
		return
	}

	reason, h = a.testIPAccess(ac, wsvc, request)
	newExtraHeaders.merge(h)
	if reason != "" {
		return
	}

	reason, h = a.testDomainAccess(ac, wsvc, request)
	newExtraHeaders.merge(h)

	if !ac.TestAccess(wsvc.Name) {
		return
	}
	reason = CerberusReasonOK
	return
}

func (a *Authenticator) testPriority(ac AccessTokensCacheEntry, wsvc WebservicesCacheEntry) (CerberusReason, CerberusExtraHeaders) {
	newExtraHeaders := make(CerberusExtraHeaders)
	priority := ac.Spec.Priority
	minPriority := wsvc.Spec.MinimumTokenPriority
	if priority < minPriority {
		newExtraHeaders[CerberusHeaderAccessLimitReason] = TokenPriorityLowerThanServiceMinAccessLimit
		newExtraHeaders[CerberusHeaderTokenPriority] = fmt.Sprint(priority)
		newExtraHeaders[CerberusHeaderWebServiceMinPriority] = fmt.Sprint(minPriority)
		return CerberusReasonAccessLimited, newExtraHeaders
	}
	return "", newExtraHeaders
}

func (a *Authenticator) testIPAccess(ac AccessTokensCacheEntry, wsvc WebservicesCacheEntry, request *Request) (CerberusReason, CerberusExtraHeaders) {
	newExtraHeaders := make(CerberusExtraHeaders)
	if len(ac.Spec.AllowedIPs) > 0 {
		ipList := make([]string, 0)

		// Retrieve "x-forwarded-for" and "referrer" headers from the request
		xForwardedFor := request.Request.Header.Get("x-forwarded-for")
		if xForwardedFor != "" {
			ips := strings.Split(xForwardedFor, ", ")
			ipList = append(ipList, ips...)
		}

		// Retrieve "remoteAddr" from the request
		remoteAddr := request.Request.RemoteAddr
		host, _, err := net.SplitHostPort(remoteAddr)
		if err != nil {
			return CerberusReasonInvalidSourceIp, newExtraHeaders
		}
		if net.ParseIP(host) == nil {
			return CerberusReasonEmptySourceIp, newExtraHeaders
		}
		ipList = append(ipList, host)

		// Check if IgnoreIP is true, skip IP list check
		if !wsvc.Spec.IgnoreIP {
			ipAllowed, err := checkIP(ipList, ac.Spec.AllowedIPs)
			if err != nil {
				return CerberusReasonBadIpList, newExtraHeaders
			}
			if !ipAllowed {
				return CerberusReasonIpNotAllowed, newExtraHeaders
			}
		}
	}
	return "", newExtraHeaders
}

func (a *Authenticator) testDomainAccess(ac AccessTokensCacheEntry, wsvc WebservicesCacheEntry, request *Request) (CerberusReason, CerberusExtraHeaders) {
	newExtraHeaders := make(CerberusExtraHeaders)
	var referrer string
	referrer = request.Request.Header.Get("referrer")

	// Check if IgnoreDomain is true, skip domain list check
	if !wsvc.Spec.IgnoreDomain && len(ac.Spec.AllowedDomains) > 0 && referrer != "" {
		domainAllowed, err := CheckDomain(referrer, ac.Spec.AllowedDomains)
		if err != nil {
			return CerberusReasonBadDomainList, newExtraHeaders
		}
		if !domainAllowed {
			return CerberusReasonDomainNotAllowed, newExtraHeaders
		}
	}
	return "", newExtraHeaders
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
func (a *Authenticator) readService(wsvc string) (bool, CerberusReason, WebservicesCacheEntry) {
	a.cacheLock.RLock()
	cacheReaders.Inc()
	defer a.cacheLock.RUnlock()
	defer cacheReaders.Dec()

	res, ok := a.webservicesCache.ReadWebservice(wsvc)
	if !ok {
		return false, CerberusReasonWebserviceNotFound, WebservicesCacheEntry{}
	}
	return true, "", res
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
	if reason != "" {
		return generateResponse(false, reason, nil), nil
	}
	wsvc = v1alpha1.WebserviceReference{
		Name:      wsvc,
		Namespace: ns,
	}.LocalName()

	request.Context[HasUpstreamAuth] = "false"
	var extraHeaders ExtraHeaders

	ok, reason, wsvcCacheEntry := a.readService(wsvc)
	if ok {
		var cerberusExtraHeaders CerberusExtraHeaders
		reason, cerberusExtraHeaders = a.TestAccess(request, wsvcCacheEntry)
		extraHeaders = toExtraHeaders(cerberusExtraHeaders)
		if reason == CerberusReasonOK && hasUpstreamAuth(wsvcCacheEntry) {
			request.Context[HasUpstreamAuth] = "true"
			ok, reason = a.checkServiceUpstreamAuth(wsvcCacheEntry, request, &extraHeaders, ctx)
		}
	}

	var err error
	if reason == CerberusReasonUpstreamAuthTimeout || reason == CerberusReasonUpstreamAuthFailed {
		err = status.Error(codes.DeadlineExceeded, "Timeout exceeded")
	}

	return generateResponse(ok, reason, extraHeaders), err
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

// NewAuthenticator creates new Authenticator object with given logger.
// currently it's not returning any error
func NewAuthenticator(logger logr.Logger) (*Authenticator, error) {
	a := Authenticator{
		logger:     logger,
		httpClient: &http.Client{},
	}
	return &a, nil
}

// checkIP checks if given ip is a member of given CIDR networks or not
// ipAllowList should be CIDR notation of the networks or net.ParseError will be retuned
func checkIP(ips []string, ipAllowList []string) (bool, error) {
	for _, ip := range ips {
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
func (a *Authenticator) checkServiceUpstreamAuth(service WebservicesCacheEntry, request *Request, extraHeaders *ExtraHeaders, ctx context.Context) (bool, CerberusReason) {
	downstreamDeadline, hasDownstreamDeadline := ctx.Deadline()
	serviceUpstreamAuthCalls.With(AddWithDownstreamDeadline(nil, hasDownstreamDeadline)).Inc()

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
		return false, CerberusReasonUpstreamAuthNoReq
	}

	req.Header = http.Header{
		service.Spec.UpstreamHttpAuth.WriteTokenTo: {token},
		"Content-Type": {"application/json"},
	}

	a.httpClient.Timeout = time.Duration(service.Spec.UpstreamHttpAuth.Timeout) * time.Millisecond
	if hasDownstreamDeadline {
		if time.Until(downstreamDeadline)-downstreamDeadlineOffset < a.httpClient.Timeout {
			a.httpClient.Timeout = time.Until(downstreamDeadline) - downstreamDeadlineOffset
		}
	}

	reqStart := time.Now()
	resp, err := a.httpClient.Do(req)
	reqDuration := time.Since(reqStart)
	if err != nil {
		urlErr, ok := err.(*url.Error)
		if ok && urlErr != nil && urlErr.Timeout() {
			return false, CerberusReasonUpstreamAuthTimeout
		}
		return false, CerberusReasonUpstreamAuthFailed
	}

	labels := AddWithDownstreamDeadline(AddStatusLabel(nil, resp.StatusCode), hasDownstreamDeadline)
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
func hasUpstreamAuth(service WebservicesCacheEntry) bool {
	return service.Spec.UpstreamHttpAuth.Address != ""
}

func generateResponse(ok bool, reason CerberusReason, extraHeaders ExtraHeaders) *Response {
	var httpStatusCode int
	if ok {
		httpStatusCode = http.StatusOK
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

func (ch CerberusExtraHeaders) merge(h CerberusExtraHeaders) {
	for key, value := range h {
		ch[key] = value
	}
}

func (ch CerberusExtraHeaders) set(key CerberusHeaderName, value string) {
	ch[key] = value
}
