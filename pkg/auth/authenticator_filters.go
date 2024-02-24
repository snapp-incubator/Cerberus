package auth

import (
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"strings"
)

// AuthenticationValidation Validation for IP restrictions
type AuthenticationValidation interface {
	Validate(ac *AccessTokensCacheEntry, wc *WebservicesCacheEntry, request *Request) (CerberusReason, CerberusExtraHeaders)
}

type AuthenticatorPriorityValidation struct{}

var _ AuthenticationValidation = (*AuthenticatorPriorityValidation)(nil)

func (apt *AuthenticatorPriorityValidation) Validate(ac *AccessTokensCacheEntry,
	wsvc *WebservicesCacheEntry, _ *Request) (CerberusReason, CerberusExtraHeaders) {

	newExtraHeaders := make(CerberusExtraHeaders)
	priority := ac.Spec.Priority
	minPriority := wsvc.Spec.MinimumTokenPriority
	if priority < minPriority {
		newExtraHeaders[CerberusHeaderAccessLimitReason] = TokenPriorityLowerThanServiceMinAccessLimit
		newExtraHeaders[CerberusHeaderTokenPriority] = fmt.Sprint(priority)
		newExtraHeaders[CerberusHeaderWebServiceMinPriority] = fmt.Sprint(minPriority)
		return CerberusReasonAccessLimited, newExtraHeaders
	}
	return CerberusReasonNotSet, newExtraHeaders
}

type AuthenticationIPValidation struct{}

var _ AuthenticationValidation = (*AuthenticationIPValidation)(nil)

// getIPListFromRequest extract IP addresses from request and it's headers
func getIPListFromRequest(request *http.Request) (CerberusReason, []string) {
	ipList := make([]string, 0)

	// Retrieve "x-forwarded-for" and "referrer" headers from the request
	xForwardedFor := request.Header.Get("x-forwarded-for")
	if xForwardedFor != "" {
		ips := strings.Split(xForwardedFor, ", ")
		ipList = append(ipList, ips...)
	}

	// Retrieve "remoteAddr" from the request
	remoteAddr := request.RemoteAddr
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return CerberusReasonInvalidSourceIp, nil
	}

	if net.ParseIP(host) == nil {
		return CerberusReasonEmptySourceIp, nil
	}

	ipList = append(ipList, host)
	return CerberusReasonNotSet, ipList
}

// Validate validates IP access restrictions
func (ait *AuthenticationIPValidation) Validate(
	ac *AccessTokensCacheEntry, wsvc *WebservicesCacheEntry, request *Request) (CerberusReason, CerberusExtraHeaders) {
	newExtraHeaders := make(CerberusExtraHeaders)
	if len(ac.Spec.AllowedIPs) > 0 {

		reason, ipList := getIPListFromRequest(&request.Request)
		if reason != CerberusReasonNotSet {
			return reason, newExtraHeaders
		}

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
	return CerberusReasonNotSet, newExtraHeaders

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

// AuthenticationDomainValidation validates for domain definitions
type AuthenticationDomainValidation struct{}

var _ AuthenticationValidation = (*AuthenticationDomainValidation)(nil)

// Validate checks domain restrictions
func (adv *AuthenticationDomainValidation) Validate(ac *AccessTokensCacheEntry,
	wsvc *WebservicesCacheEntry, request *Request) (CerberusReason, CerberusExtraHeaders) {

	newExtraHeaders := make(CerberusExtraHeaders)
	referrer := request.Request.Header.Get("referrer")

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
	return CerberusReasonNotSet, newExtraHeaders

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

// AuthenticationTokenAccessValidation check for token and webservice access
type AuthenticationTokenAccessValidation struct{}

var _ AuthenticationValidation = (*AuthenticationTokenAccessValidation)(nil)

// Validate checks token and webservice access
func (adv *AuthenticationTokenAccessValidation) Validate(ac *AccessTokensCacheEntry,
	wsvc *WebservicesCacheEntry, request *Request) (CerberusReason, CerberusExtraHeaders) {
	if !ac.TestAccess(wsvc.Name) {
		return CerberusReasonWebserviceNotAllowed, CerberusExtraHeaders{}
	}
	return CerberusReasonNotSet, CerberusExtraHeaders{}
}
