package auth

// CerberusReason is the type which is used to identfies the reason
// that caused Cerberus to accept/reject the request.
type CerberusReason string

const (
	// CerberusReasonOK means that Cerberus finds no error in the request
	// and the request is Authenticated for next actions. All CerberusReasons
	// OTHER THAN CerberusReasonOK means that the request is NOT authenticated
	CerberusReasonOK CerberusReason = "ok"

	// CerberusReasonNotSet means no reason is set during checks and it means
	// the process should continue to find the reason
	CerberusReasonNotSet CerberusReason = ""

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

	// CerberusReasonWebserviceNotAllowed means that given webservice in
	// the request context is empty or it's not given at all
	CerberusReasonWebserviceNotAllowed CerberusReason = "webservice-not-allowed"

	// CerberusReasonWebserviceNamespaceEmpty means that given namespace of webservice in
	// the request context is empty or it's not given at all
	CerberusReasonWebserviceNamespaceEmpty CerberusReason = "webservice-namespace-empty"

	// CerberusReasonInvalidUpstreamAddress means that requested webservice
	// has an invalid upstream address in it's manifest
	CerberusReasonInvalidUpstreamAddress CerberusReason = "invalid-auth-upstream"

	// CerberusReasonUpstreamAuthHeaderEmpty means that request header that
	// should be forwarded to upstream auth service is empty
	CerberusReasonUpstreamAuthHeaderEmpty CerberusReason = "upstream-auth-header-empty"

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

	// CerberusReasonUpstreamAuthServiceIsOverloaded indicates that the upstream authentication service
	// is currently overloaded and unable to process new requests
	CerberusReasonUpstreamAuthServiceIsOverloaded CerberusReason = "upstream-auth-service-is-overloaded"
)
