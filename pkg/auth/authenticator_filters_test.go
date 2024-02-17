package auth

import (
	"net/http"
	"testing"

	"github.com/snapp-incubator/Cerberus/api/v1alpha1"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestCheckIP(t *testing.T) {
	// Test case 1: Empty IP allow list
	ips := []string{"192.168.1.1"}
	ipAllowList := []string{}
	allowed, err := checkIP(ips, ipAllowList)
	assert.NoError(t, err, "No error should occur")
	assert.False(t, allowed, "IP should not be allowed")

	// Test case 2: IP is allowed
	ips = []string{"192.168.1.1"}
	ipAllowList = []string{"192.168.1.0/24"}
	allowed, err = checkIP(ips, ipAllowList)
	assert.NoError(t, err, "No error should occur")
	assert.True(t, allowed, "IP should be allowed")

	// Test case 3: IP is not allowed
	ips = []string{"192.168.2.1"}
	ipAllowList = []string{"192.168.1.0/24"}
	allowed, err = checkIP(ips, ipAllowList)
	assert.NoError(t, err, "No error should occur")
	assert.False(t, allowed, "IP should not be allowed")

	// Test case 4: Error while parsing IP allow list
	ips = []string{"192.168.1.1"}
	ipAllowList = []string{"invalidCIDR"}
	allowed, err = checkIP(ips, ipAllowList)
	assert.Error(t, err, "Error should occur")
	assert.False(t, allowed, "IP should not be allowed due to error")
	assert.EqualError(t, err, "invalid CIDR address: invalidCIDR", "Error message should indicate invalid CIDR")
}

func TestCheckDomainComplex(t *testing.T) {
	testCases := []struct {
		domain         string
		domainAllowed  []string
		expectedResult bool
	}{
		// Exact domain matches
		{"example.com", []string{"example.com"}, true},
		{"sub.example.com", []string{"sub.example.com"}, true},
		{"sub.sub.example.com", []string{"sub.sub.example.com"}, true},

		// Wildcard prefix and suffix matches
		{"sub.example.com", []string{"*.example.com"}, true},
		{"example.net", []string{"example.*"}, true},

		// Multiple patterns with mixed results
		{"example.com", []string{"example.net", "*.example.com", "example.*"}, true},
		{"sub.sub.example.net", []string{"*.example.com", "example.*"}, false},
		{"example.org", []string{"*.example.com", "example.*"}, true},

		// Case-insensitive matching
		{"ExAmPlE.CoM", []string{"example.com"}, true},

		// Character class [a-z0-9]
		{"example1.com", []string{"example[0-9].com"}, true},
		{"examplea.com", []string{"example[a-z].com"}, true},
		{"exampleA.com", []string{"example[a-z].com"}, true},

		// Multiple * wildcards
		{"sub.sub.example.net", []string{"*.sub.*.net"}, true},
		{"sub.sub.example.net", []string{"*.*.*.net"}, true},
		{"sub.sub.example.net", []string{"*.example.net"}, true},

		// ? wildcard character
		{"example1.com", []string{"example?.com"}, true},
		{"example12.com", []string{"example?.com"}, false},
	}

	for _, tc := range testCases {
		result, err := CheckDomain(tc.domain, tc.domainAllowed)
		if result != tc.expectedResult {
			t.Errorf("Domain: %s, Expected: %v, Got: %v", tc.domain, tc.expectedResult, result)
		}
		if err != nil {
			t.Errorf("Domain: %s, Expected Error: nil, Got Error: %v", tc.domain, err)
		}
	}
}

func TestAuthenticationDomainValidation_Validate(t *testing.T) {
	// Test case 1: When IgnoreDomain is false, and referrer is in allowed domains
	ac := &AccessTokensCacheEntry{
		AccessToken: v1alpha1.AccessToken{
			Spec: v1alpha1.AccessTokenSpec{AllowedDomains: []string{"example.com", "example.org"}},
		},
	}
	wsvc := &WebservicesCacheEntry{WebService: v1alpha1.WebService{Spec: v1alpha1.WebServiceSpec{IgnoreDomain: false}}}

	request := &Request{Request: http.Request{Header: http.Header{}}}
	request.Request.Header.Set("referrer", "example.com")

	auth := &AuthenticationDomainValidation{}
	wsvc.Spec.IgnoreDomain = false
	reason, headers := auth.Validate(ac, wsvc, request)
	assert.Equal(t, CerberusReasonNotSet, reason, "Expected reason should be NotSet")
	assert.Empty(t, headers, "Expected headers should be empty")

	// Test case 2: When IgnoreDomain is true
	request.Request.Header.Set("referrer", "random")
	wsvc.Spec.IgnoreDomain = true
	reason, headers = auth.Validate(ac, wsvc, request)
	assert.Equal(t, CerberusReasonNotSet, reason, "Expected reason should be NotSet")
	assert.Empty(t, headers, "Expected headers should be empty")

	// Test case 3: When IgnoreDomain is true, and referrer is not in allowed domains
	wsvc.Spec.IgnoreDomain = false
	request.Request.Header.Set("referrer", "x.com")
	reason, headers = auth.Validate(ac, wsvc, request)
	assert.Equal(t, CerberusReasonDomainNotAllowed, reason, "Expected reason should be DomainNotAllowed")
	assert.Empty(t, headers, "Expected headers should be empty")

	// Test case 4: When IgnoreDomain is true, and referrer is bad
	wsvc.Spec.IgnoreDomain = false
	request.Request.Header.Set("referrer", "x.com")
	ac.Spec.AllowedDomains = []string{"["}
	reason, headers = auth.Validate(ac, wsvc, request)
	assert.Equal(t, CerberusReasonBadDomainList, reason, "Expected reason should be BadDomainList")
	assert.Empty(t, headers, "Expected headers should be empty")

	// Test case 5: When no allowed domains are specified
	ac.Spec.AllowedDomains = nil
	wsvc.Spec.IgnoreDomain = false
	reason, headers = auth.Validate(ac, wsvc, request)
	assert.Equal(t, CerberusReasonNotSet, reason, "Expected reason should be NotSet")
	assert.Empty(t, headers, "Expected headers should be empty")
}

func TestAuthenticationTokenAccessValidation_Validate(t *testing.T) {
	wsvc := WebservicesCacheEntry{}
	wsvc.allowedNamespacesCache = make(AllowedNamespacesCache)
	wsvc.allowedNamespacesCache["test-ns"] = struct{}{}
	wsvc.Name = "test-ws"
	wsvc.Namespace = "test-ns"
	ac := AccessTokensCacheEntry{}
	ac.AccessToken = v1alpha1.AccessToken{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-token",
			Namespace: "test-ns",
		},
	}
	ac.allowedWebservicesCache = make(AllowedWebservicesCache)
	ac.allowedWebservicesCache["test-ws"] = struct{}{}

	atcv := AuthenticationTokenAccessValidation{}

	reason, _ := atcv.Validate(&ac, &wsvc, nil)
	assert.Equal(t, reason, CerberusReasonNotSet)

	ac.allowedWebservicesCache = make(AllowedWebservicesCache)
	ac.allowedWebservicesCache["test-ws-2"] = struct{}{}
	reason, _ = atcv.Validate(&ac, &wsvc, nil)
	assert.Equal(t, reason, CerberusReasonWebserviceNotAllowed)
}

func TestGetIPListFromRequest(t *testing.T) {
	// Test case 1: Valid x-forwarded-for header and remote address
	request := &http.Request{
		Header:     http.Header{"X-Forwarded-For": {"192.0.2.1, 198.51.100.2"}},
		RemoteAddr: "192.0.2.3:12345",
	}
	reason, ipList := getIPListFromRequest(request)
	assert.Equal(t, CerberusReasonNotSet, reason)
	assert.ElementsMatch(t, []string{"192.0.2.1", "198.51.100.2", "192.0.2.3"}, ipList)

	// Test case 2: Valid remote address only
	request = &http.Request{
		RemoteAddr: "192.0.2.3:12345",
	}
	reason, ipList = getIPListFromRequest(request)
	assert.Equal(t, CerberusReasonNotSet, reason)
	assert.ElementsMatch(t, []string{"192.0.2.3"}, ipList)

	// Test case 3: Invalid remote address
	request = &http.Request{
		RemoteAddr: "[invalid]",
	}
	reason, ipList = getIPListFromRequest(request)
	assert.Equal(t, CerberusReasonInvalidSourceIp, reason)
	assert.Nil(t, ipList)

	// Test case 4: Empty x-forwarded-for header, valid remote address
	request = &http.Request{
		RemoteAddr: "192.0.2.3:12345",
	}
	reason, ipList = getIPListFromRequest(request)
	assert.Equal(t, CerberusReasonNotSet, reason)
	assert.ElementsMatch(t, []string{"192.0.2.3"}, ipList)

	// Test case 5: Empty x-forwarded-for header, invalid remote address
	request = &http.Request{
		RemoteAddr: "[invalid]",
	}
	reason, ipList = getIPListFromRequest(request)
	assert.Equal(t, CerberusReasonInvalidSourceIp, reason)
	assert.Nil(t, ipList)

	// Test case 6: Empty x-forwarded-for header and remote address
	request = &http.Request{}
	reason, ipList = getIPListFromRequest(request)
	assert.Equal(t, CerberusReasonInvalidSourceIp, reason)
	assert.Nil(t, ipList)

	// Test case 7: Empty x-forwarded-for header and invalid remote address
	request = &http.Request{
		RemoteAddr: "192.168.1.1.1:80",
	}
	reason, ipList = getIPListFromRequest(request)
	assert.Equal(t, CerberusReasonEmptySourceIp, reason)
	assert.Nil(t, ipList)
}
