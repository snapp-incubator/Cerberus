package auth

import (
	"fmt"
	"testing"
)

var (
	ipAllowList     = generateIPAllowList(10000)    // Generate a large IP allow list
	domainAllowList = generateDomainAllowList(1000) // Generate a large domain allow list
	testIP          = "192.168.0.1"                 // Use a valid IP for testing
	testDomain      = "example.com"                 // Use a valid domain for testing
)

func generateIPAllowList(size int) []string {
	// Generate a large IP allow list with unique subnets
	ipList := make([]string, size)
	for i := 0; i < size; i++ {
		ipList[i] = fmt.Sprintf("192.168.0.%d", i)
	}
	return ipList
}

func generateDomainAllowList(size int) []string {
	// Generate a large domain allow list with unique patterns
	domainList := make([]string, size)
	for i := 0; i < size; i++ {
		domainList[i] = fmt.Sprintf("example%d.com", i)

	}
	return domainList
}

func BenchmarkCheckIPWithLargeInput(b *testing.B) {
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = checkIP(testIP, ipAllowList)
	}
}

func BenchmarkCheckDomainWithLargeInput(b *testing.B) {
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = CheckDomain(testDomain, domainAllowList)
	}
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
