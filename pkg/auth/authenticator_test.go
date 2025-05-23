package auth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net" // Added
	"net/http"
	"net/url"
	"sort" // Added
	"strings"
	"testing"
	"time"

	cerberusv1alpha1 "github.com/snapp-incubator/Cerberus/api/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var (
	ipAllowList     = generateIPAllowList(10000)    // Generate a large IP allow list
	domainAllowList = generateDomainAllowList(1000) // Generate a large domain allow list
	testIP          = "192.168.0.1"                 // Use a valid IP for testing
	testDomain      = "example.com"                 // Use a valid domain for testing
	subjects        = generateSubjects(2)           // Generates ["subject-1", "subject-2"]
	webservices     = generateWebservices(2)        // Generates ["webservice-1", "webservice-2"]
)

// generateIPAllowList Generate a large IP allow list with unique subnets
func generateIPAllowList(size int) []string {
	ipList := make([]string, size)
	for i := 0; i < size; i++ {
		ipList[i] = fmt.Sprintf("192.168.0.%d", i)
	}
	return ipList
}

// generateDomainAllowList Generate a large domain allow list with unique patterns
func generateDomainAllowList(size int) []string {
	domainList := make([]string, size)
	for i := 0; i < size; i++ {
		domainList[i] = fmt.Sprintf("example%d.com", i)

	}
	return domainList
}

// generateSubjects create a list of subjects in form of string array
func generateSubjects(subjectCount int) []string {
	subject := make([]string, subjectCount)

	for i := 0; i < subjectCount; i++ {
		subject[i] = fmt.Sprintf("subject-%d", i+1)
	}

	return subject
}

// generateWebservices create a list of webservices in form of LocalWebserviceReference array
func generateWebservices(webserviceCount int) []cerberusv1alpha1.LocalWebserviceReference {
	webservice := make([]cerberusv1alpha1.LocalWebserviceReference, webserviceCount)

	for i := 0; i < webserviceCount; i++ {
		webservice[i].Name = fmt.Sprintf("webservice-%d", i+1)
	}

	return webservice
}

func BenchmarkCheckIPWithLargeInput(b *testing.B) {
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = checkIP([]string{testIP}, ipAllowList)
	}
}

func BenchmarkCheckDomainWithLargeInput(b *testing.B) {
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = CheckDomain(testDomain, domainAllowList)
	}
}

func TestReadService(t *testing.T) {
	authenticator := &Authenticator{
		accessTokensCache: &AccessTokensCache{},
		webservicesCache:  &WebservicesCache{},
	}

	request := &Request{
		Context: map[string]string{
			"webservice": "SampleWebService",
		},
		Request: http.Request{
			Header: http.Header{},
		},
	}

	// Create a test WebserviceCacheEntry
	webservice := WebservicesCacheEntry{
		WebService: cerberusv1alpha1.WebService{
			Spec: cerberusv1alpha1.WebServiceSpec{
				LookupHeader: "X-Cerberus-Token",
			},
		},
	}

	(*authenticator.webservicesCache)["SampleWebService"] = webservice

	request.Request.Header.Set("X-Cerberus-Token", "test-token")

	wsvc := request.Context["webservice"]

	testCases := []struct {
		wsvc               string
		expectedOk         bool
		expectedReason     CerberusReason
		expectedCacheEntry WebservicesCacheEntry
	}{
		{wsvc, true, CerberusReasonNotSet, webservice},
		{"nonexistent_service", false, CerberusReasonWebserviceNotFound, WebservicesCacheEntry{}},
	}

	for _, tc := range testCases {
		t.Run(tc.wsvc, func(t *testing.T) {
			reason, _ := authenticator.readService(tc.wsvc)
			if reason != tc.expectedReason {
				t.Errorf("Expected reason: %v, Got: %v", tc.expectedReason, reason)
			}
			// if ok {
			//TODO: Check cache entry fields, e.g., cacheEntry.SomeField
			// }
		})
	}
}

func TestReadToken(t *testing.T) {

	authenticator := &Authenticator{}

	request := &Request{
		Request: http.Request{
			Header: http.Header{},
		},
	}

	// Create a test WebserviceCacheEntry
	webservice := WebservicesCacheEntry{
		WebService: cerberusv1alpha1.WebService{
			Spec: cerberusv1alpha1.WebServiceSpec{
				LookupHeader: string(CerberusHeaderAccessToken),
			},
		},
	}

	request.Request.Header.Set(string(CerberusHeaderAccessToken), "test-token")

	reason, token := authenticator.readToken(request, webservice)

	assert.Equal(t, reason, CerberusReasonNotSet, "Expected reason to be empty.")
	assert.Equalf(t, token, "test-token", "Expected token to be 'test-token'. Got: %s", token)

	webservice.Spec.LookupHeader = ""
	reason, _ = authenticator.readToken(request, webservice)
	assert.Equal(t, reason, CerberusReasonLookupIdentifierEmpty, "lookup-identifier-empty")

}

func TestUpdateCache(t *testing.T) {
	// Create a fake Kubernetes client and an Authenticator instance.
	fakeClient, authenticator := setupTestEnvironment(t)

	// Create and prepare mock data for Kubernetes resources.
	accessTokens := prepareAccessTokens(2)
	bindings := prepareWebserviceAccessBindings(2)
	webservices := prepareWebservices(2)
	secrets := prepareSecrets(2)

	createAccessTokens(t, fakeClient, accessTokens[0], accessTokens[1])
	createBindings(t, fakeClient, bindings[0], bindings[1])
	createWebservices(t, fakeClient, webservices[0], webservices[1])
	createSecrets(t, fakeClient, secrets[0], secrets[1])

	// Call the UpdateCache function.
	err := authenticator.UpdateCache(fakeClient, context.Background(), false)

	// Check if the cache update was successful.
	assert.NoError(t, err)

	// Assert that the caches have been populated correctly.
	assertCachesPopulated(t, authenticator)
}

func TestTestAccessValidToken(t *testing.T) {
	authenticator := &Authenticator{
		accessTokensCache: &AccessTokensCache{},
		webservicesCache:  &WebservicesCache{},
	}

	tokenEntry := AccessTokensCacheEntry{
		AccessToken: cerberusv1alpha1.AccessToken{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "valid-token",
				Namespace: "SampleNamespace",
			},
		},
		allowedWebservicesCache: map[string]struct{}{
			"SampleNamespace/SampleWebService": {},
		},
	}
	(*authenticator.accessTokensCache)["valid-token"] = tokenEntry

	headers := http.Header{}
	headers.Set(string(CerberusHeaderAccessToken), "valid-token")

	request := &Request{
		Context: map[string]string{
			"webservice": "SampleWebService",
			"namespace":  "SampleNamespace",
		},
		Request: http.Request{
			Header: headers,
		},
	}

	webservice := WebservicesCacheEntry{
		WebService: cerberusv1alpha1.WebService{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "SampleWebService",
				Namespace: "SampleNamespace",
			},
			Spec: cerberusv1alpha1.WebServiceSpec{
				LookupHeader: string(CerberusHeaderAccessToken),
			},
		},
	}
	(*authenticator.webservicesCache)["SampleWebService"] = webservice

	reason, extraHeaders := authenticator.TestAccess(request, webservice)

	assert.Equal(t, CerberusReasonNotSet, reason, "Expected reason to be OK")
	assert.Equal(t, "SampleNamespace/valid-token", extraHeaders[CerberusHeaderAccessToken], "Expected token in extraHeaders")
	assert.Equal(t, "SampleNamespace/SampleWebService", extraHeaders[CerberusHeaderWebservice], "Expected webservice in extraHeader")
}

func TestTestAccessInvalidToken(t *testing.T) {
	authenticator := &Authenticator{
		accessTokensCache: &AccessTokensCache{},
		webservicesCache:  &WebservicesCache{},
	}

	headers := http.Header{}
	headers.Set("X-Cerberus-Token", "invalid-token")

	request := &Request{
		Context: map[string]string{
			"webservice": "SampleWebService",
		},
		Request: http.Request{
			Header: headers,
		},
	}

	webservice := WebservicesCacheEntry{
		WebService: cerberusv1alpha1.WebService{
			ObjectMeta: metav1.ObjectMeta{
				Name: "SampleWebService",
			},
			Spec: cerberusv1alpha1.WebServiceSpec{
				LookupHeader: "X-Cerberus-Token",
			},
		},
	}

	(*authenticator.webservicesCache)["SampleWebService"] = webservice

	reason, extraHeaders := authenticator.TestAccess(request, webservice)

	assert.Equal(t, CerberusReasonTokenNotFound, reason, "Expected reason to be TokenNotFound")
	assert.Empty(t, extraHeaders, "Expected no extra headers for invalid token")
}

func TestTestAccessEmptyToken(t *testing.T) {
	authenticator := &Authenticator{
		accessTokensCache: &AccessTokensCache{},
		webservicesCache:  &WebservicesCache{},
	}

	headers := http.Header{}
	headers.Set(string(CerberusHeaderAccessToken), "")

	request := &Request{
		Context: map[string]string{
			"webservice": "SampleWebService",
		},
		Request: http.Request{
			Header: headers,
		},
	}

	webservice := WebservicesCacheEntry{
		WebService: cerberusv1alpha1.WebService{
			ObjectMeta: metav1.ObjectMeta{
				Name: "SampleWebService",
			},
			Spec: cerberusv1alpha1.WebServiceSpec{
				LookupHeader: string(CerberusHeaderAccessToken),
			},
		},
	}

	(*authenticator.webservicesCache)["SampleWebService"] = webservice

	reason, extraHeaders := authenticator.TestAccess(request, webservice)

	assert.Equal(t, CerberusReasonTokenEmpty, reason, "Expected reason to be TokenEmpty")
	assert.Empty(t, extraHeaders, "Expected no extra headers for empty token")
}

func TestTestAccessBadIPList(t *testing.T) {
	authenticator := &Authenticator{
		accessTokensCache: &AccessTokensCache{},
		webservicesCache:  &WebservicesCache{},
		validators: []AuthenticationValidation{
			&AuthenticationIPValidation{},
		},
	}

	tokenEntry := AccessTokensCacheEntry{
		AccessToken: cerberusv1alpha1.AccessToken{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "valid-token",
				Namespace: "SampleNamespace",
			},
			Spec: cerberusv1alpha1.AccessTokenSpec{
				AllowedIPs: []string{"192.168.1.1", "192.168.1.2"},
			},
		},
		allowedWebservicesCache: map[string]struct{}{
			"SampleWebService": {},
		},
	}
	(*authenticator.accessTokensCache)["valid-token"] = tokenEntry

	// Assuming an IP not in the allow list
	headers := http.Header{}
	headers.Set(string(CerberusHeaderAccessToken), "valid-token")
	headers.Set("X-Forwarded-For", "192.168.1.3")

	request := &Request{
		Context: map[string]string{
			"webservice": "SampleWebService",
		},
		Request: http.Request{
			Header:     headers,
			RemoteAddr: "192.168.1.3:12345",
		},
	}

	webservice := WebservicesCacheEntry{
		WebService: cerberusv1alpha1.WebService{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "SampleWebService",
				Namespace: "SampleNamespace",
			},
			Spec: cerberusv1alpha1.WebServiceSpec{
				LookupHeader: string(CerberusHeaderAccessToken),
			},
		},
	}

	(*authenticator.webservicesCache)["SampleNamespace/SampleWebService"] = webservice

	reason, extraHeaders := authenticator.TestAccess(request, webservice)

	assert.Equal(t, CerberusReasonBadIpList, reason, "Expected reason to be BadIpList")
	assert.Equal(t, extraHeaders[CerberusHeaderAccessToken], "SampleNamespace/valid-token", "Expected AccessToken LocalName as a Header")
	assert.Equal(t, extraHeaders[CerberusHeaderWebservice], "SampleNamespace/SampleWebService", "Expected Webservice LocalName as a Header")
}

func TestTestAccessLimited(t *testing.T) {
	authenticator := &Authenticator{
		accessTokensCache: &AccessTokensCache{},
		webservicesCache:  &WebservicesCache{},
		validators:        defineValidators(),
	}

	// Assuming an a token with lower Priority than WebService threshold
	tokenEntry := AccessTokensCacheEntry{
		AccessToken: cerberusv1alpha1.AccessToken{
			ObjectMeta: metav1.ObjectMeta{
				Name: "valid-token",
			},
			Spec: cerberusv1alpha1.AccessTokenSpec{
				Priority: 50,
			},
		},
		allowedWebservicesCache: map[string]struct{}{
			"SampleWebService": {},
		},
	}
	(*authenticator.accessTokensCache)["valid-token"] = tokenEntry

	headers := http.Header{}
	headers.Set(string(CerberusHeaderAccessToken), "valid-token")

	request := &Request{
		Context: map[string]string{
			"webservice": "SampleWebService",
		},
		Request: http.Request{
			Header: headers,
		},
	}

	webservice := WebservicesCacheEntry{
		WebService: cerberusv1alpha1.WebService{
			ObjectMeta: metav1.ObjectMeta{
				Name: "SampleWebService",
			},
			Spec: cerberusv1alpha1.WebServiceSpec{
				LookupHeader:         string(CerberusHeaderAccessToken),
				MinimumTokenPriority: 100,
			},
		},
	}

	(*authenticator.webservicesCache)["SampleWebService"] = webservice

	reason, extraHeaders := authenticator.TestAccess(request, webservice)

	assert.Equal(t, CerberusReasonAccessLimited, reason, "Expected reason to be AccessLimited")
	assert.Equal(t, extraHeaders[CerberusHeaderAccessLimitReason], TokenPriorityLowerThanServiceMinAccessLimit)
	assert.Equal(t, extraHeaders[CerberusHeaderTokenPriority], fmt.Sprint(tokenEntry.Spec.Priority))
	assert.Equal(t, extraHeaders[CerberusHeaderWebServiceMinPriority], fmt.Sprint(webservice.Spec.MinimumTokenPriority))

}

// setupTestEnvironment create test environment for kubernetes client enabled
// tests to mock the apis.
func setupTestEnvironment(t *testing.T) (client.Client, *Authenticator) {
	// Initialize a Kubernetes client's scheme.
	scheme := runtime.NewScheme()

	// Register the custom resource type with the scheme.
	err := cerberusv1alpha1.AddToScheme(scheme)
	if err != nil {
		t.Fatalf("Failed to add cerberusv1alpha1 to scheme: %v", err)
	}

	err = corev1.AddToScheme(scheme)
	if err != nil {
		t.Fatalf("Failed to add corev1 to scheme: %v", err)
	}

	// Create a fake Kubernetes client using the registered scheme.
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	// Create an Authenticator instance.
	authenticator := &Authenticator{}

	return fakeClient, authenticator
}

// prepareAccessTokens create a list of test AccessTokens for tests
func prepareAccessTokens(count int) []cerberusv1alpha1.AccessToken {

	// Create and prepare access tokens with unique names.
	accessTokens := make([]cerberusv1alpha1.AccessToken, count)
	for i := 0; i < count; i++ {
		tokenName := fmt.Sprintf("test-token-%d", i)
		accessTokens[i] = cerberusv1alpha1.AccessToken{
			ObjectMeta: metav1.ObjectMeta{Name: tokenName},
			Spec: cerberusv1alpha1.AccessTokenSpec{
				State:          "active",
				AllowedIPs:     ipAllowList,
				AllowedDomains: domainAllowList,
			},
		}
	}
	return accessTokens
}

// prepareWebserviceAccessBindings create a list of test WebserviceAccessBindings for tests
func prepareWebserviceAccessBindings(count int) []cerberusv1alpha1.WebserviceAccessBinding {
	// Create and prepare webservice access bindings with unique names.
	bindings := make([]cerberusv1alpha1.WebserviceAccessBinding, count)
	for i := 0; i < count; i++ {
		bindingName := fmt.Sprintf("test-binding-%d", i)
		bindings[i] = cerberusv1alpha1.WebserviceAccessBinding{
			ObjectMeta: metav1.ObjectMeta{Name: bindingName, Namespace: "default"},
			Spec: cerberusv1alpha1.WebserviceAccessBindingSpec{
				Subjects:    subjects,
				Webservices: webservices,
			},
		}
	}
	return bindings
}

// prepareWebservices creates a list of WebServices for tests
func prepareWebservices(count int) []cerberusv1alpha1.WebService {
	// Create and prepare webservice resources with unique names.
	webservices := make([]cerberusv1alpha1.WebService, count)
	for i := 0; i < count; i++ {
		webserviceName := fmt.Sprintf("test-service-%d", i)
		webservices[i] = cerberusv1alpha1.WebService{
			ObjectMeta: metav1.ObjectMeta{Name: webserviceName, Namespace: "default"},
			Spec: cerberusv1alpha1.WebServiceSpec{
				LookupHeader: string(CerberusHeaderAccessToken),
				UpstreamHttpAuth: cerberusv1alpha1.UpstreamHttpAuthService{
					Address:       "http://example.com/auth",
					ReadTokenFrom: "Authorization",
					WriteTokenTo:  string(CerberusHeaderAccessToken),
				},
			},
		}
	}
	return webservices
}

// prepareWebservices creates a list of WebServices for tests
func prepareSecrets(count int) []corev1.Secret {
	// Create and prepare secrets with unique names.
	secrets := make([]corev1.Secret, count)
	for i := 0; i < count; i++ {
		secretName := fmt.Sprintf("test-secret-%d", i)
		secrets[i] = corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: "default"},
			Data: map[string][]byte{
				"token": []byte("test-token-value"),
			},
		}
	}
	return secrets
}

// createAccessTokens creates a list of access tokens in kubernetes fake client
func createAccessTokens(t *testing.T, fakeClient client.Client, accessTokens ...cerberusv1alpha1.AccessToken) {
	ctx := context.Background()
	for _, token := range accessTokens {
		assert.NoError(t, fakeClient.Create(ctx, &token))
	}
}

// createBindings creates a list of bindings in kubernetes fake client
func createBindings(t *testing.T, fakeClient client.Client, bindings ...cerberusv1alpha1.WebserviceAccessBinding) {
	ctx := context.Background()
	for _, binding := range bindings {
		assert.NoError(t, fakeClient.Create(ctx, &binding))
	}
}

// createWebservices creates a list of Webservices in kubernetes fake client
func createWebservices(t *testing.T, fakeClient client.Client, webservices ...cerberusv1alpha1.WebService) {
	ctx := context.Background()
	for _, service := range webservices {
		assert.NoError(t, fakeClient.Create(ctx, &service))
	}
}

// createSecrets creates a list of secrets in kubernetes fake client
func createSecrets(t *testing.T, fakeClient client.Client, secrets ...corev1.Secret) {
	ctx := context.Background()
	for _, secret := range secrets {
		assert.NoError(t, fakeClient.Create(ctx, &secret))
	}
}

// assertCachesPopulated asserts that webservicesCache is populated.
// authenticator.accessTokensCache is not supported yet
func assertCachesPopulated(t *testing.T, authenticator *Authenticator) {
	authenticator.cacheLock.RLock()
	defer authenticator.cacheLock.RUnlock()

	//TODO: check this error
	//assert.NotEmpty(t, authenticator.accessTokensCache)
	assert.NotEmpty(t, authenticator.webservicesCache)
}

func TestToExtraHeaders(t *testing.T) {
	// Test case 1: Empty input
	emptyInput := CerberusExtraHeaders{}
	result := toExtraHeaders(emptyInput)
	assert.Empty(t, result, "Result should be empty for empty input")

	// Test case 2: Input with multiple headers
	input := CerberusExtraHeaders{
		"Header1": "Value1",
		"Header2": "Value2",
		"Header3": "Value3",
	}
	expected := ExtraHeaders{
		"Header1": "Value1",
		"Header2": "Value2",
		"Header3": "Value3",
	}
	result = toExtraHeaders(input)
	assert.Equal(t, expected, result, "Result should match expected extra headers")

	// Test case 3: Input with a single header
	singleHeaderInput := CerberusExtraHeaders{
		"Header": "Value",
	}
	singleExpected := ExtraHeaders{
		"Header": "Value",
	}
	singleResult := toExtraHeaders(singleHeaderInput)
	assert.Equal(t, singleExpected, singleResult, "Result should match expected extra headers")
}

func TestCheckDomain(t *testing.T) {
	// Test case 1: Domain matches one of the GLOB patterns
	domain := "example.com"
	domainAllowedList := []string{"*.com", "*.org", "example.*"}
	matched, err := CheckDomain(domain, domainAllowedList)
	assert.NoError(t, err, "No error should occur")
	assert.True(t, matched, "Domain should match one of the GLOB patterns")

	// Test case 2: Domain matches one of the GLOB patterns and it
	// does not care about the case
	domain = "ExampLe.Com"
	domainAllowedList = []string{"*.CoM", "*.org", "eXample.*"}
	matched, err = CheckDomain(domain, domainAllowedList)
	assert.NoError(t, err, "No error should occur")
	assert.True(t, matched, "Domain should match one of the GLOB patterns")

	// Test case 3: Domain does not match any of the GLOB patterns
	domain = "example.net"
	domainAllowedList = []string{"*.com", "*.org", "google.*"}
	matched, err = CheckDomain(domain, domainAllowedList)
	assert.NoError(t, err, "No error should occur")
	assert.False(t, matched, "Domain should not match any of the GLOB patterns")

	// Test case 4: Error while matching the domain with GLOB patterns
	domain = "example.com"
	domainAllowedList = []string{"[invalid pattern"}
	matched, err = CheckDomain(domain, domainAllowedList)
	assert.Error(t, err, "Error should occur")
	assert.False(t, matched, "Domain should not match due to error")
	assert.EqualError(t, err, "syntax error in pattern", "Error message should indicate syntax error")
}

func Test_hasUpstreamAuth(t *testing.T) {
	wsce := WebservicesCacheEntry{
		WebService: cerberusv1alpha1.WebService{
			Spec: cerberusv1alpha1.WebServiceSpec{
				UpstreamHttpAuth: cerberusv1alpha1.UpstreamHttpAuthService{
					Address: "",
				},
			},
		},
	}
	assert.False(t, hasUpstreamAuth(wsce))
	wsce.Spec.UpstreamHttpAuth.Address = "anything"

	assert.True(t, hasUpstreamAuth(wsce))

}

func TestCerberusExtraHeaders_merge_set(t *testing.T) {
	h := CerberusExtraHeaders{}

	h.merge(CerberusExtraHeaders{"a": "b"})

	assert.Len(t, h, 1)
	assert.Equal(t, h["a"], "b")

	h.merge(CerberusExtraHeaders{"a": "c", "x": "y", "z": "w"})
	assert.Len(t, h, 3)
	assert.Equal(t, h["a"], "c") //Overwritten
	assert.Equal(t, h["x"], "y") // Newly added
	assert.Equal(t, h["z"], "w") // Newly added

	h.set(CerberusHeaderAccessToken, "test")

	assert.Equal(t, h[CerberusHeaderAccessToken], "test")
}

func Test_readRequestContext(t *testing.T) {
	// Test case 1: Valid context keys
	request := &Request{
		Context: map[string]string{
			"webservice": "example-service",
			"namespace":  "example-namespace",
		},
	}
	wsvc, ns, reason := readRequestContext(request)
	assert.Equal(t, "example-service", wsvc, "Webservice should match expected value")
	assert.Equal(t, "example-namespace", ns, "Namespace should match expected value")
	assert.Empty(t, reason, "Reason should be empty")

	// Test case 2: Webservice key missing
	request = &Request{
		Context: map[string]string{
			"namespace": "example-namespace",
		},
	}
	wsvc, ns, reason = readRequestContext(request)
	assert.Empty(t, wsvc, "Webservice should be empty")
	assert.Empty(t, ns, "Namespace should be empty")
	assert.Equal(t, CerberusReasonWebserviceEmpty, reason, "Reason should indicate webservice key missing")

	// Test case 3: Namespace key missing
	request = &Request{
		Context: map[string]string{
			"webservice": "example-service",
		},
	}
	wsvc, ns, reason = readRequestContext(request)
	assert.Empty(t, wsvc, "Webservice should be empty")
	assert.Empty(t, ns, "Namespace should be empty")
	assert.Equal(t, CerberusReasonWebserviceNamespaceEmpty, reason, "Reason should indicate namespace key missing")

	// Test case 4: Both keys missing
	request = &Request{
		Context: map[string]string{},
	}
	wsvc, ns, reason = readRequestContext(request)
	assert.Empty(t, wsvc, "Webservice should be empty")
	assert.Empty(t, ns, "Namespace should be empty")
	assert.Equal(t, CerberusReasonWebserviceEmpty, reason, "Reason should indicate webservice key missing")
}

func Test_generateResponse(t *testing.T) {
	// Test case 1: Response is allowed with no extra headers
	expectedResponse := &Response{
		Allow: true,
		Response: http.Response{
			StatusCode: http.StatusOK,
			Header: http.Header{
				ExternalAuthHandlerHeader:  {"cerberus"},
				CerberusHeaderReasonHeader: {string(CerberusReasonOK)},
			},
		},
	}
	actualResponse := generateResponse("", nil)
	assert.Equal(t, expectedResponse.Allow, actualResponse.Allow, "Response should be allowed")
	assert.Equal(t, expectedResponse.Response.StatusCode, actualResponse.Response.StatusCode, "HTTP status code should match")
	assert.Equal(t, expectedResponse.Response.Header, actualResponse.Response.Header, "Response headers should match")

	// Test case 2: Response is not allowed with extra headers
	extraHeaders := ExtraHeaders{"Extra-Header": "value"}
	expectedResponse = &Response{
		Allow: false,
		Response: http.Response{
			StatusCode: http.StatusUnauthorized,
			Header: http.Header{
				ExternalAuthHandlerHeader:  {"cerberus"},
				CerberusHeaderReasonHeader: {"reason"},
				"Extra-Header":             {"value"},
			},
		},
	}
	actualResponse = generateResponse("reason", extraHeaders)
	assert.Equal(t, expectedResponse.Allow, actualResponse.Allow, "Response should not be allowed")
	assert.Equal(t, expectedResponse.Response.StatusCode, actualResponse.Response.StatusCode, "HTTP status code should match")
	assert.Equal(t, expectedResponse.Response.Header, actualResponse.Response.Header, "Response headers should match")
}

func TestValidateUpstreamAuthRequest(t *testing.T) {
	// Test case 1: ReadTokenFrom and WriteTokenTo are empty
	service := WebservicesCacheEntry{}
	service.Spec.UpstreamHttpAuth.ReadTokenFrom = ""
	service.Spec.UpstreamHttpAuth.WriteTokenTo = ""
	reason := validateUpstreamAuthRequest(service.Spec.UpstreamHttpAuth)
	assert.Equal(t, CerberusReasonTargetAuthTokenEmpty, reason, "Expected target auth token empty")

	// Test case 2: WriteTokenTo is empty
	service = WebservicesCacheEntry{}
	service.Spec.UpstreamHttpAuth.ReadTokenFrom = "token"
	service.Spec.UpstreamHttpAuth.WriteTokenTo = ""
	reason = validateUpstreamAuthRequest(service.Spec.UpstreamHttpAuth)
	assert.Equal(t, CerberusReasonTargetAuthTokenEmpty, reason, "Expected target auth token empty")

	// Test case 3: ReadTokenFrom is empty
	service = WebservicesCacheEntry{}
	service.Spec.UpstreamHttpAuth.ReadTokenFrom = ""
	service.Spec.UpstreamHttpAuth.WriteTokenTo = "token"
	reason = validateUpstreamAuthRequest(service.Spec.UpstreamHttpAuth)
	assert.Equal(t, CerberusReasonTargetAuthTokenEmpty, reason, "Expected target auth token empty")

	// Test case 4: Address is invalid
	service = WebservicesCacheEntry{}
	service.Spec.UpstreamHttpAuth.ReadTokenFrom = "token"
	service.Spec.UpstreamHttpAuth.WriteTokenTo = "token"
	service.Spec.UpstreamHttpAuth.Address = "not a valid URL"
	reason = validateUpstreamAuthRequest(service.Spec.UpstreamHttpAuth)
	assert.Equal(t, CerberusReasonInvalidUpstreamAddress, reason, "Expected invalid upstream address")

	// Test case 5: Everything is valid
	service = WebservicesCacheEntry{}
	service.Spec.UpstreamHttpAuth.ReadTokenFrom = "token"
	service.Spec.UpstreamHttpAuth.WriteTokenTo = "token"
	service.Spec.UpstreamHttpAuth.Address = "http://example.com"
	reason = validateUpstreamAuthRequest(service.Spec.UpstreamHttpAuth)
	assert.Empty(t, reason, "Expected no reason")
}

// MockHTTPClient is a mock implementation of http.Client for testing purposes.
type MockTransport struct {
	DoFunc func(req *http.Request) (*http.Response, error)
}

// Do executes the provided HTTP request and returns the response.
func (c *MockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return c.DoFunc(req)
}

func TestAdjustTimeoutWithHTTPClientMock(t *testing.T) {
	// Test case 1: No downstream deadline
	transport := &MockTransport{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			// Mock response
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       http.NoBody,
			}, nil
		},
	}

	authenticator := Authenticator{
		httpClient: &http.Client{Transport: transport},
	}

	// TestCase 1: No deadline
	timeout := 1000
	downstreamDeadline := time.Now()
	hasDownstreamDeadline := false

	expectedTimeout := time.Duration(1000) * time.Millisecond
	authenticator.adjustTimeout(timeout, downstreamDeadline, hasDownstreamDeadline)
	assert.Equal(t, expectedTimeout, authenticator.httpClient.Timeout, "Timeout should match expected value")

	// TestCase 2, With deadline but it is a bad test because it is not deterministic
	timeout = 1000
	downstreamDeadline = time.Now().Add(time.Duration(1000) * time.Millisecond)
	hasDownstreamDeadline = true
	expectedTimeout = time.Duration(1000)*time.Millisecond - downstreamDeadlineOffset
	authenticator.adjustTimeout(timeout, downstreamDeadline, hasDownstreamDeadline)
	assert.NotEqual(t, expectedTimeout, authenticator.httpClient.Timeout)
	assert.LessOrEqual(t, expectedTimeout-authenticator.httpClient.Timeout, time.Duration(50)*time.Microsecond, "Timeout should match expected value")

	// TestCase 3, With deadline but it is more than httpTimeout
	timeout = 10
	downstreamDeadline = time.Now().Add(time.Duration(100) * time.Millisecond)
	hasDownstreamDeadline = true
	expectedTimeout = time.Duration(10) * time.Millisecond
	authenticator.adjustTimeout(timeout, downstreamDeadline, hasDownstreamDeadline)
	assert.Equal(t, expectedTimeout, authenticator.httpClient.Timeout, "Timeout should match expected value")

}

func TestCopyUpstreamHeaders(t *testing.T) {
	// Test case 1: Header is copied to extraHeaders
	resp := &http.Response{
		Header: http.Header{
			"Header1": {"Value1"},
			"Header2": {"Value2"},
		},
	}
	extraHeaders := make(ExtraHeaders)
	careHeaders := []string{"Header1"}

	copyUpstreamHeaders(resp, &extraHeaders, careHeaders)
	assert.Equal(t, "Value1", extraHeaders["Header1"], "Header1 should be copied to extraHeaders")
	assert.Empty(t, extraHeaders["Header2"], "Header2 should not be copied to extraHeaders")

	// Test case 2: No headers are copied
	resp = &http.Response{
		Header: http.Header{
			"Header1": {"Value1"},
			"Header2": {"Value2"},
		},
	}
	extraHeaders = make(ExtraHeaders)
	careHeaders = []string{}

	copyUpstreamHeaders(resp, &extraHeaders, careHeaders)
	assert.Empty(t, extraHeaders, "No headers should be copied to extraHeaders")

	// Test case 3: Multiple headers are copied
	resp = &http.Response{
		Header: http.Header{
			"Header1": {"Value1"},
			"Header2": {"Value2"},
			"Header3": {"Value3"},
		},
	}
	extraHeaders = make(ExtraHeaders)
	careHeaders = []string{"Header1", "Header3"}

	copyUpstreamHeaders(resp, &extraHeaders, careHeaders)
	assert.Equal(t, "Value1", extraHeaders["Header1"], "Header1 should be copied to extraHeaders")
	assert.Empty(t, extraHeaders["Header2"], "Header2 should not be copied to extraHeaders")
	assert.Equal(t, "Value3", extraHeaders["Header3"], "Header3 should be copied to extraHeaders")
}

// Mock error interface with timeout interface implementation for
// testing timeout errors in tests
type innerError struct {
	timeout bool
}

func (inner innerError) Timeout() bool {
	return true
}

func (inner innerError) Error() string {
	panic("should not be used")
}
func TestProcessResponseError(t *testing.T) {
	// Test case 1: No error
	reason := processResponseError(nil)
	assert.Equal(t, CerberusReasonNotSet, reason, "No error should return an empty string")

	// Test case 2: Timeout error
	urlErr := &url.Error{
		Op:  "Get",
		URL: "http://example.com",
		Err: &innerError{timeout: true},
	}
	reason = processResponseError(urlErr)
	assert.Equal(t, CerberusReasonUpstreamAuthTimeout, reason, "Timeout error should return upstream auth timeout")

	// Test case 2: Timeout error
	urlErr = &url.Error{
		Op:  "Get",
		URL: "http://example.com",
		Err: errors.New("no timeout implemeted"),
	}
	reason = processResponseError(urlErr)
	assert.Equal(t, CerberusReasonUpstreamAuthFailed, reason, "Timeout error should return upstream auth timeout")

	// Test case 3: Other error
	reason = processResponseError(errors.New("connection refused"))
	assert.Equal(t, CerberusReasonUpstreamAuthFailed, reason, "Other errors should return upstream auth failed")
}

func TestSetupUpstreamAuthRequest(t *testing.T) {
	// Test case 1: Successful setup
	upstreamAuth := &cerberusv1alpha1.UpstreamHttpAuthService{
		ReadTokenFrom: "X-Token-Read",
		WriteTokenTo:  "X-Token-Write",
		Address:       "http://example.com",
		Timeout:       1000,
	}

	request := &Request{
		Request: http.Request{
			Header: http.Header{
				"X-Token-Read": {"value"},
			},
		},
	}

	expectedReq, _ := http.NewRequest("GET", "http://example.com", nil)
	expectedReq.Header = http.Header{
		"X-Token-Write": {"value"},
		"Content-Type":  {"application/json"},
	}
	token := request.Request.Header.Get(upstreamAuth.ReadTokenFrom)
	actualReq, actualErr := setupUpstreamAuthRequest(upstreamAuth, token, http.Header{})
	assert.NoError(t, actualErr, "No error should occur")
	assert.Equal(t, expectedReq.URL.String(), actualReq.URL.String(), "Request URL should match")
	assert.Equal(t, expectedReq.Header, actualReq.Header, "Request headers should match")

	// Test case 2: Error from http.NewRequest
	upstreamAuth = &cerberusv1alpha1.UpstreamHttpAuthService{
		Address: ":",
	} // Empty service
	request = &Request{}

	actualReq, actualErr = setupUpstreamAuthRequest(upstreamAuth, "", http.Header{})
	assert.Nil(t, actualReq, "Request should be nil when there is an error")
	assert.Error(t, actualErr, "Error should occur when service is empty")
}

func TestCheck_SuccessfulAuthentication(t *testing.T) {
	mockHTTPClient := &http.Client{
		Transport: &MockTransport{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader("")),
				}, nil
			},
		},
	}

	authenticator := &Authenticator{
		httpClient:        mockHTTPClient,
		accessTokensCache: &AccessTokensCache{},
		webservicesCache:  &WebservicesCache{},
	}
	tokens := prepareAccessTokens(1)
	services := prepareWebservices(1)

	tokenEntry := AccessTokensCacheEntry{
		AccessToken: tokens[0],
		allowedWebservicesCache: map[string]struct{}{
			"default/webservice-1": {},
		},
	}
	(*authenticator.accessTokensCache)["valid-token"] = tokenEntry

	headers := http.Header{}
	headers.Set(string(CerberusHeaderAccessToken), "valid-token")

	request := &Request{
		Context: map[string]string{
			"webservice": services[0].Name,
			"namespace":  "default",
		},
		Request: http.Request{
			Header: headers,
		},
	}

	webserviceKey := fmt.Sprintf("%s/%s", "default", services[0].Name)
	authenticator.webservicesCache = &WebservicesCache{
		webserviceKey: WebservicesCacheEntry{WebService: services[0]},
	}

	finalResponse, err := authenticator.Check(context.Background(), request)

	assert.NoError(t, err, "Expected no error for successful authentication")
	assert.NotNil(t, finalResponse, "Expected a non-nil response for successful authentication")
	assert.True(t, finalResponse.Allow, "Expected the request to be allowed for valid token and service")
}

func TestCheck_TokenNotFound(t *testing.T) {
	authenticator := &Authenticator{
		accessTokensCache: &AccessTokensCache{},
		webservicesCache:  &WebservicesCache{},
	}

	services := prepareWebservices(1)

	headers := http.Header{}
	headers.Set(string(CerberusHeaderAccessToken), "nonexistent-token")

	request := &Request{
		Context: map[string]string{
			"webservice": services[0].Name,
			"namespace":  "default",
		},
		Request: http.Request{
			Header: headers,
		},
	}

	webserviceKey := fmt.Sprintf("%s/%s", "default", services[0].Name)
	authenticator.webservicesCache = &WebservicesCache{
		webserviceKey: WebservicesCacheEntry{WebService: services[0]},
	}

	finalResponse, err := authenticator.Check(context.Background(), request)

	assert.NoError(t, err, "Expected no error from Check function itself")
	assert.NotNil(t, finalResponse, "Expected a non-nil response even for token not found scenario")
	assert.False(t, finalResponse.Allow, "Expected the request to not be allowed due to token not found")
	assert.Contains(t, finalResponse.Response.Header.Get("X-Cerberus-Reason"), "token-not-found", "Expected X-Cerberus-Reason header to indicate token not found")
}

func TestCheck_ServiceNotFound(t *testing.T) {
	authenticator := &Authenticator{
		accessTokensCache: &AccessTokensCache{},
		webservicesCache:  &WebservicesCache{},
	}

	tokens := prepareAccessTokens(1)

	tokenEntry := AccessTokensCacheEntry{
		AccessToken:             tokens[0],
		allowedWebservicesCache: map[string]struct{}{},
	}
	(*authenticator.accessTokensCache)["valid-token"] = tokenEntry

	headers := http.Header{}
	headers.Set(string(CerberusHeaderAccessToken), "valid-token")

	request := &Request{
		Context: map[string]string{
			"webservice": "nonexistent-service",
			"namespace":  "default",
		},
		Request: http.Request{
			Header: headers,
		},
	}

	finalResponse, err := authenticator.Check(context.Background(), request)

	assert.NoError(t, err, "Expected no error even if service is not found")
	assert.NotNil(t, finalResponse, "Expected a non-nil response even if service is not found")
	assert.False(t, finalResponse.Allow, "Expected the request to be denied due to service not found")
	assert.Contains(t, finalResponse.Response.Header.Get("X-Cerberus-Reason"), "webservice-notfound", "Expected webservice-notfound reason")
}

func TestCheck_EmptyToken(t *testing.T) {
	authenticator := &Authenticator{
		accessTokensCache: &AccessTokensCache{},
		webservicesCache:  &WebservicesCache{},
	}
	services := prepareWebservices(1)

	webserviceKey := fmt.Sprintf("%s/%s", "default", services[0].Name)
	(*authenticator.webservicesCache)[webserviceKey] = WebservicesCacheEntry{WebService: services[0]}

	headers := http.Header{}

	request := &Request{
		Context: map[string]string{
			"webservice": services[0].Name,
			"namespace":  "default",
		},
		Request: http.Request{
			Header: headers,
		},
	}

	finalResponse, err := authenticator.Check(context.Background(), request)

	assert.NoError(t, err, "Expected no error for empty token scenario")
	assert.NotNil(t, finalResponse, "Expected a non-nil response for empty token scenario")
	assert.False(t, finalResponse.Allow, "Expected the request to be denied due to empty token")
	assert.Equal(t, http.StatusUnauthorized, finalResponse.Response.StatusCode, "Expected a 401 Unauthorized status code")
	assert.Contains(t, finalResponse.Response.Header.Get("X-Cerberus-Reason"), "token-empty", "Expected reason to indicate empty token")
}

func TestCheck_InvalidServiceName(t *testing.T) {
	authenticator := &Authenticator{
		accessTokensCache: &AccessTokensCache{},
		webservicesCache:  &WebservicesCache{},
	}
	tokens := prepareAccessTokens(1)

	tokenEntry := AccessTokensCacheEntry{
		AccessToken: tokens[0],
		allowedWebservicesCache: map[string]struct{}{
			"default/valid-service": {},
		},
	}
	(*authenticator.accessTokensCache)["valid-token"] = tokenEntry

	headers := http.Header{}
	headers.Set(string(CerberusHeaderAccessToken), "valid-token")

	request := &Request{
		Context: map[string]string{
			"webservice": "invalid-service",
			"namespace":  "default",
		},
		Request: http.Request{
			Header: headers,
		},
	}

	finalResponse, err := authenticator.Check(context.Background(), request)

	assert.NoError(t, err, "Expected no error for invalid service name scenario")
	assert.NotNil(t, finalResponse, "Expected a non-nil response for invalid service name scenario")
	assert.False(t, finalResponse.Allow, "Expected the request to be denied due to invalid service name")
	assert.Equal(t, http.StatusUnauthorized, finalResponse.Response.StatusCode, "Expected a 401 Unauthorized status code")
	assert.Contains(t, finalResponse.Response.Header.Get("X-Cerberus-Reason"), "webservice-notfound", "Expected reason to indicate service not found")
}

func TestCheck_UpstreamAuthUnauthorized(t *testing.T) {
	mockHTTPClient := &http.Client{
		Transport: &MockTransport{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusUnauthorized,
					Body:       io.NopCloser(strings.NewReader("Unauthorized")),
				}, nil
			},
		},
	}

	authenticator := &Authenticator{
		httpClient:        mockHTTPClient,
		accessTokensCache: &AccessTokensCache{},
		webservicesCache:  &WebservicesCache{},
	}

	services := prepareWebservices(1)
	tokens := prepareAccessTokens(1)

	tokenEntry := AccessTokensCacheEntry{
		AccessToken: tokens[0],
		allowedWebservicesCache: map[string]struct{}{
			"default/" + services[0].Name: {},
		},
	}
	(*authenticator.accessTokensCache)["valid-token"] = tokenEntry

	webserviceKey := fmt.Sprintf("%s/%s", "default", services[0].Name)
	(*authenticator.webservicesCache)[webserviceKey] = WebservicesCacheEntry{WebService: services[0]}

	headers := http.Header{}
	headers.Set(string(CerberusHeaderAccessToken), "valid-token")

	request := &Request{
		Context: map[string]string{
			"webservice": services[0].Name,
			"namespace":  "default",
		},
		Request: http.Request{
			Header: headers,
		},
	}

	finalResponse, err := authenticator.Check(context.Background(), request)

	assert.NoError(t, err, "Did not expect an error from Check function")
	assert.NotNil(t, finalResponse, "Expected a non-nil response")
	assert.False(t, finalResponse.Allow, "Expected the request to be denied due to unauthorized upstream authentication")
	assert.Equal(t, "unauthorized", finalResponse.Response.Header.Get("X-Cerberus-Reason"), "Expected reason to indicate unauthorized")
}

func TestCheck_UpstreamAuthFailed(t *testing.T) {
	mockHTTPClient := &http.Client{
		Transport: &MockTransport{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
						StatusCode: http.StatusRequestTimeout,
						Body:       io.NopCloser(strings.NewReader("Internal Server Error")),
						Header:     make(http.Header),
					}, &url.Error{
						Op:  "Get",
						URL: "http://fake-upstream-service/authenticate",
						Err: errors.New("Internal Server Error"),
					}
			},
		},
	}

	authenticator := &Authenticator{
		httpClient:        mockHTTPClient,
		accessTokensCache: &AccessTokensCache{},
		webservicesCache:  &WebservicesCache{},
	}

	services := prepareWebservices(1)
	tokens := prepareAccessTokens(1)

	tokenEntry := AccessTokensCacheEntry{
		AccessToken: tokens[0],
		allowedWebservicesCache: map[string]struct{}{
			"default/" + services[0].Name: {},
		},
	}
	(*authenticator.accessTokensCache)["valid-token"] = tokenEntry

	webserviceKey := fmt.Sprintf("%s/%s", "default", services[0].Name)
	(*authenticator.webservicesCache)[webserviceKey] = WebservicesCacheEntry{WebService: services[0]}

	headers := http.Header{}
	headers.Set(string(CerberusHeaderAccessToken), "valid-token")

	request := &Request{
		Context: map[string]string{
			"webservice": services[0].Name,
			"namespace":  "default",
		},
		Request: http.Request{
			Header: headers,
		},
	}

	finalResponse, err := authenticator.Check(context.Background(), request)

	assert.Error(t, err, "Error should occur")
	assert.NotNil(t, finalResponse, "Expected a non-nil response")
	assert.False(t, finalResponse.Allow, "Expected the request to be denied due to upstream authentication failed")
	assert.Equal(t, "upstream-auth-failed", finalResponse.Response.Header.Get("X-Cerberus-Reason"), "Expected reason to indicate upstream authentication failed")
}

func TestCheck_UpstreamAuthTimeout(t *testing.T) {
	mockHTTPClient := &http.Client{
		Transport: &MockTransport{
			DoFunc: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
						StatusCode: http.StatusRequestTimeout,
						Body:       io.NopCloser(strings.NewReader("Request Timeout")),
						Header:     make(http.Header),
					}, &url.Error{
						Op:  "Get",
						URL: "http://fake-upstream-service/authenticate",
						Err: &innerError{timeout: true},
					}
			},
		},
	}

	authenticator := &Authenticator{
		httpClient:        mockHTTPClient,
		accessTokensCache: &AccessTokensCache{},
		webservicesCache:  &WebservicesCache{},
	}

	services := prepareWebservices(1)
	tokens := prepareAccessTokens(1)

	tokenEntry := AccessTokensCacheEntry{
		AccessToken: tokens[0],
		allowedWebservicesCache: map[string]struct{}{
			"default/" + services[0].Name: {},
		},
	}
	(*authenticator.accessTokensCache)["valid-token"] = tokenEntry

	webserviceKey := fmt.Sprintf("%s/%s", "default", services[0].Name)
	(*authenticator.webservicesCache)[webserviceKey] = WebservicesCacheEntry{WebService: services[0]}

	headers := http.Header{}
	headers.Set(string(CerberusHeaderAccessToken), "valid-token")

	request := &Request{
		Context: map[string]string{
			"webservice": services[0].Name,
			"namespace":  "default",
		},
		Request: http.Request{
			Header: headers,
		},
	}

	finalResponse, err := authenticator.Check(context.Background(), request)

	assert.Error(t, err, "Error should occur")
	assert.NotNil(t, finalResponse, "Expected a non-nil response")
	assert.False(t, finalResponse.Allow, "Expected the request to be denied due to upstream authentication timeout")
	assert.Equal(t, "upstream-auth-timeout", finalResponse.Response.Header.Get("X-Cerberus-Reason"), "Expected reason to indicate upstream authentication timeout")
}

// MockAuthServer provides a mock HTTP server for testing upstream authentication.
type MockAuthServer struct {
	Server                 *http.Server
	URL                    string
	ExpectedStatus         int
	ExpectedRequestHeaders http.Header // Use http.Header for more robust checking
	ResponseHeaders        http.Header // Use http.Header for setting response
	Called                 bool
	t                      *testing.T
	handlerFunc            http.HandlerFunc // Store the handler to allow modification if needed, though not used in current tests
}

// NewMockAuthServer creates and starts a new MockAuthServer.
// The caller is responsible for closing the server using MockAuthServer.Close().
func NewMockAuthServer(t *testing.T) *MockAuthServer {
	mock := &MockAuthServer{
		t:                      t,
		ExpectedStatus:         http.StatusOK, // Default to OK
		ExpectedRequestHeaders: make(http.Header),
		ResponseHeaders:        make(http.Header),
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0") // Listen on a random available port
	if err != nil {
		t.Fatalf("Failed to listen on a port: %v", err)
	}
	mock.URL = "http://" + listener.Addr().String()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mock.Called = true
		// Check request headers
		for key, expectedValues := range mock.ExpectedRequestHeaders {
			actualValues := r.Header.Values(key) // Use Values to get all for a header
			if !assert.ObjectsAreEqualValues(expectedValues, actualValues) {
				// Using assert.ObjectsAreEqualValues for slice comparison is tricky.
				// A simple string join might be better for error reporting if order doesn't matter,
				// or a more sophisticated slice comparison if it does.
				// For now, let's check if all expected values are present.
				match := true
				if len(expectedValues) != len(actualValues) {
					match = false
				} else {
					expectedCopy := append([]string(nil), expectedValues...)
					actualCopy := append([]string(nil), actualValues...)
					sort.Strings(expectedCopy)
					sort.Strings(actualCopy)
					if !assert.ObjectsAreEqualValues(expectedCopy, actualCopy) {
						match = false
					}
				}
				if !match {
					mock.t.Errorf("MockAuthServer: Header mismatch for %s: expected %s, got %s", key, expectedValues, actualValues)
				}
			}
		}

		// Set response headers
		for key, values := range mock.ResponseHeaders {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}

		w.WriteHeader(mock.ExpectedStatus)
		// Optionally write a body if needed for future tests
		// if mock.ResponseBody != "" {
		//	 w.Write([]byte(mock.ResponseBody))
		// }
	})
	mock.handlerFunc = handler // Store for potential future modification, not used now.
	mock.Server = &http.Server{Handler: handler, Addr: listener.Addr().String()}

	go func() {
		// ServeHTTP will block until the listener is closed or an error occurs.
		// We don't check for http.ErrServerClosed as that's expected on Close().
		if err := mock.Server.Serve(listener); err != nil && err != http.ErrServerClosed {
			mock.t.Logf("MockAuthServer.Serve error: %v", err) // Use Logf for non-fatal errors in goroutines
		}
	}()

	return mock
}

// Close stops the mock server.
func (m *MockAuthServer) Close() {
	if m.Server != nil {
		// Shutdown is more graceful, but Close is fine for httptest style mocks.
		// Using a context with Shutdown for more complex scenarios.
		err := m.Server.Close() // Close immediately.
		if err != nil {
			m.t.Logf("Error closing mock server: %v", err)
		}
	}
}

func TestAuthenticator_Check_MultipleUpstreamAuth(t *testing.T) {
	// Common setup for authenticator and basic caches
	setupAuthenticator := func() *Authenticator {
		return &Authenticator{
			httpClient:        &http.Client{Timeout: 5 * time.Second}, // Give a default timeout
			accessTokensCache: &AccessTokensCache{},
			webservicesCache:  &WebservicesCache{},
			validators:        defineValidators(), // Include standard validators
		}
	}

	// Helper to create a WebservicesCacheEntry, allowing specification of both new and deprecated fields
	createWebserviceEntry := func(namespace, name string, lookupHeader string,
		upstreamAuths []cerberusv1alpha1.UpstreamHttpAuthService, // For new UpstreamHttpAuths field
		deprecatedUpstreamAuth *cerberusv1alpha1.UpstreamHttpAuthService) WebservicesCacheEntry { // For old UpstreamHttpAuth field

		spec := cerberusv1alpha1.WebServiceSpec{
			LookupHeader:      lookupHeader,
			UpstreamHttpAuths: upstreamAuths,
		}
		if deprecatedUpstreamAuth != nil {
			spec.UpstreamHttpAuth = *deprecatedUpstreamAuth
		}

		return WebservicesCacheEntry{
			WebService: cerberusv1alpha1.WebService{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
				Spec:       spec,
			},
		}
	}

	// Helper to create an AccessTokensCacheEntry
	createTokenEntry := func(token, namespace, serviceName string) AccessTokensCacheEntry {
		return AccessTokensCacheEntry{
			AccessToken: cerberusv1alpha1.AccessToken{
				ObjectMeta: metav1.ObjectMeta{Name: token, Namespace: namespace},
				Spec: cerberusv1alpha1.AccessTokenSpec{
					State: "active",
				},
			},
			allowedWebservicesCache: map[string]struct{}{
				namespace + "/" + serviceName: {},
			},
		}
	}

	t.Run("Successful chain (2 upstreams)", func(t *testing.T) {
		auth := setupAuthenticator()
		wsNamespace := "testns"
		wsName := "multi-ws-ok"
		clientTokenValue := "client-initial-token"
		clientTokenHeader := "X-Client-Token"

		// Mock Upstream 1
		mockUpstream1 := NewMockAuthServer(t)
		defer mockUpstream1.Close()
		mockUpstream1.ExpectedStatus = http.StatusOK
		mockUpstream1.ExpectedRequestHeaders.Set("U1-Auth-Header", clientTokenValue)
		mockUpstream1.ResponseHeaders.Set("U1-Care", "Val1")

		// Mock Upstream 2
		mockUpstream2 := NewMockAuthServer(t)
		defer mockUpstream2.Close()
		mockUpstream2.ExpectedStatus = http.StatusOK
		mockUpstream2.ExpectedRequestHeaders.Set("U2-Auth-Header", clientTokenValue)
		// Note: For `ExpectedRequestHeaders`, if a header from U1 (e.g., U1-Care) should be forwarded
		// and checked by U2, it needs to be explicitly added to mockUpstream2.ExpectedRequestHeaders.
		// The current logic in `checkServiceUpstreamAuth` forwards care headers.
		mockUpstream2.ResponseHeaders.Set("U2-Care", "Val2")

		upstreamServices := []cerberusv1alpha1.UpstreamHttpAuthService{
			{Address: mockUpstream1.URL, ReadTokenFrom: clientTokenHeader, WriteTokenTo: "U1-Auth-Header", CareHeaders: []string{"U1-Care"}, Timeout: 100},
			{Address: mockUpstream2.URL, ReadTokenFrom: clientTokenHeader, WriteTokenTo: "U2-Auth-Header", CareHeaders: []string{"U2-Care"}, Timeout: 100},
		}
		// Use new helper: upstreamAuths is populated, deprecatedUpstreamAuth is nil
		wsEntry := createWebserviceEntry(wsNamespace, wsName, clientTokenHeader, upstreamServices, nil)
		(*auth.webservicesCache)[wsNamespace+"/"+wsName] = wsEntry
		(*auth.accessTokensCache)[clientTokenValue] = createTokenEntry(clientTokenValue, wsNamespace, wsName)

		req := &Request{
			Context: map[string]string{"webservice": wsName, "namespace": wsNamespace},
			Request: http.Request{Header: http.Header{clientTokenHeader: {clientTokenValue}}},
		}

		resp, err := auth.Check(context.Background(), req)

		assert.NoError(t, err)
		assert.True(t, resp.Allow)
		assert.Equal(t, string(CerberusReasonOK), resp.Response.Header.Get(CerberusHeaderReasonHeader))
		assert.Equal(t, "Val1", resp.Response.Header.Get("U1-Care"))
		assert.Equal(t, "Val2", resp.Response.Header.Get("U2-Care"))
		assert.True(t, mockUpstream1.Called, "Mock Upstream 1 should have been called")
		assert.True(t, mockUpstream2.Called, "Mock Upstream 2 should have been called")
	})

	t.Run("Failure in the middle of the chain (2nd of 3 fails)", func(t *testing.T) {
		auth := setupAuthenticator()
		wsNamespace := "testns"
		wsName := "multi-ws-fail-middle"
		clientTokenValue := "client-token"
		clientTokenHeader := "X-Client-Token"

		mockUpstream1 := NewMockAuthServer(t)
		defer mockUpstream1.Close()
		mockUpstream1.ExpectedStatus = http.StatusOK // U1 is OK

		mockUpstream2 := NewMockAuthServer(t) // U2 Fails
		defer mockUpstream2.Close()
		mockUpstream2.ExpectedStatus = http.StatusUnauthorized

		mockUpstream3 := NewMockAuthServer(t) // U3 Not Called
		defer mockUpstream3.Close()

		upstreamServices := []cerberusv1alpha1.UpstreamHttpAuthService{
			{Address: mockUpstream1.URL, ReadTokenFrom: clientTokenHeader, WriteTokenTo: "U1-Auth", Timeout: 100},
			{Address: mockUpstream2.URL, ReadTokenFrom: clientTokenHeader, WriteTokenTo: "U2-Auth", Timeout: 100},
			{Address: mockUpstream3.URL, ReadTokenFrom: clientTokenHeader, WriteTokenTo: "U3-Auth", Timeout: 100},
		}
		// Use new helper: upstreamAuths is populated, deprecatedUpstreamAuth is nil
		wsEntry := createWebserviceEntry(wsNamespace, wsName, clientTokenHeader, upstreamServices, nil)
		(*auth.webservicesCache)[wsNamespace+"/"+wsName] = wsEntry
		(*auth.accessTokensCache)[clientTokenValue] = createTokenEntry(clientTokenValue, wsNamespace, wsName)

		req := &Request{
			Context: map[string]string{"webservice": wsName, "namespace": wsNamespace},
			Request: http.Request{Header: http.Header{clientTokenHeader: {clientTokenValue}}},
		}

		resp, err := auth.Check(context.Background(), req)

		assert.NoError(t, err) // Check itself doesn't error, failure is in the resp.Allow
		assert.False(t, resp.Allow)
		assert.Equal(t, string(CerberusReasonUnauthorized), resp.Response.Header.Get(CerberusHeaderReasonHeader))
		assert.True(t, mockUpstream1.Called, "Mock Upstream 1 should have been called")
		assert.True(t, mockUpstream2.Called, "Mock Upstream 2 should have been called")
		assert.False(t, mockUpstream3.Called, "Mock Upstream 3 should NOT have been called")
	})

	t.Run("Header Forwarding and Token Propagation (3 upstreams)", func(t *testing.T) {
		auth := setupAuthenticator()
		wsNamespace := "testns"
		wsName := "multi-ws-propagate"
		clientTokenValue := "initial-client-token"
		clientTokenHeader := "X-Client-Token" // Header client sends token in

		// Upstream 1: Gets client token, returns new token and a care header
		mockUpstream1 := NewMockAuthServer(t)
		defer mockUpstream1.Close()
		mockUpstream1.ExpectedStatus = http.StatusOK
		mockUpstream1.ExpectedRequestHeaders.Set("U1-Auth", clientTokenValue)
		mockUpstream1.ResponseHeaders.Set("U1-Care-Header", "U1-Value")
		mockUpstream1.ResponseHeaders.Set("Token-For-U2-Header", "TokenFromU1ForU2")

		// Upstream 2: Gets token from U1, and U1's care header. Returns its own care header. No new token.
		mockUpstream2 := NewMockAuthServer(t)
		defer mockUpstream2.Close()
		mockUpstream2.ExpectedStatus = http.StatusOK
		mockUpstream2.ExpectedRequestHeaders.Set("U2-Auth", "TokenFromU1ForU2")
		mockUpstream2.ExpectedRequestHeaders.Set("U1-Care-Header", "U1-Value") // Check forwarded header
		mockUpstream2.ResponseHeaders.Set("U2-Care-Header", "U2-Value")

		// Upstream 3: Gets original client token (as U2 didn't propagate a new one for U3). Expects U2's care header.
		mockUpstream3 := NewMockAuthServer(t)
		defer mockUpstream3.Close()
		mockUpstream3.ExpectedStatus = http.StatusOK
		mockUpstream3.ExpectedRequestHeaders.Set("U3-Auth", clientTokenValue)
		mockUpstream3.ExpectedRequestHeaders.Set("U2-Care-Header", "U2-Value") // Check forwarded header
		mockUpstream3.ResponseHeaders.Set("U3-Care-Header", "U3-Value")

		upstreamServices := []cerberusv1alpha1.UpstreamHttpAuthService{
			{
				Address:       mockUpstream1.URL,
				ReadTokenFrom: clientTokenHeader,
				WriteTokenTo:  "U1-Auth",
				CareHeaders:   []string{"U1-Care-Header", "Token-For-U2-Header"},
				Timeout:       100,
			},
			{
				Address:       mockUpstream2.URL,
				ReadTokenFrom: "Token-For-U2-Header",
				WriteTokenTo:  "U2-Auth",
				CareHeaders:   []string{"U2-Care-Header"},
				Timeout:       100,
			},
			{
				Address:       mockUpstream3.URL,
				ReadTokenFrom: clientTokenHeader, 
				WriteTokenTo:  "U3-Auth",
				CareHeaders:   []string{"U3-Care-Header"},
				Timeout:       100,
			},
		}
		// Use new helper: upstreamAuths is populated, deprecatedUpstreamAuth is nil
		wsEntry := createWebserviceEntry(wsNamespace, wsName, clientTokenHeader, upstreamServices, nil)
		(*auth.webservicesCache)[wsNamespace+"/"+wsName] = wsEntry
		(*auth.accessTokensCache)[clientTokenValue] = createTokenEntry(clientTokenValue, wsNamespace, wsName)

		req := &Request{
			Context: map[string]string{"webservice": wsName, "namespace": wsNamespace},
			Request: http.Request{Header: http.Header{clientTokenHeader: {clientTokenValue}}},
		}

		resp, err := auth.Check(context.Background(), req)

		assert.NoError(t, err)
		assert.True(t, resp.Allow)
		assert.Equal(t, string(CerberusReasonOK), resp.Response.Header.Get(CerberusHeaderReasonHeader))

		// Check accumulated CareHeaders in final response
		assert.Equal(t, "U1-Value", resp.Response.Header.Get("U1-Care-Header"))
		assert.Equal(t, "TokenFromU1ForU2", resp.Response.Header.Get("Token-For-U2-Header")) //This was a care header from U1
		assert.Equal(t, "U2-Value", resp.Response.Header.Get("U2-Care-Header"))
		assert.Equal(t, "U3-Value", resp.Response.Header.Get("U3-Care-Header"))

		assert.True(t, mockUpstream1.Called, "Mock Upstream 1 should be called")
		assert.True(t, mockUpstream2.Called, "Mock Upstream 2 should be called")
		assert.True(t, mockUpstream3.Called, "Mock Upstream 3 should be called")
	})

	t.Run("Empty Upstream Auth List", func(t *testing.T) {
		auth := setupAuthenticator()
		wsNamespace := "testns"
		wsName := "multi-ws-empty"
		clientTokenValue := "client-token"
		clientTokenHeader := "X-Client-Token"

		// Use new helper: both upstreamAuths and deprecatedUpstreamAuth are nil/empty
		wsEntry := createWebserviceEntry(wsNamespace, wsName, clientTokenHeader, nil, nil)
		(*auth.webservicesCache)[wsNamespace+"/"+wsName] = wsEntry
		(*auth.accessTokensCache)[clientTokenValue] = createTokenEntry(clientTokenValue, wsNamespace, wsName)

		req := &Request{
			Context: map[string]string{"webservice": wsName, "namespace": wsNamespace},
			Request: http.Request{Header: http.Header{clientTokenHeader: {clientTokenValue}}},
		}

		resp, err := auth.Check(context.Background(), req)

		assert.NoError(t, err)
		assert.True(t, resp.Allow) // Should be allowed as basic auth passes and no upstreams to fail
		assert.Equal(t, string(CerberusReasonOK), resp.Response.Header.Get(CerberusHeaderReasonHeader))
	})

	t.Run("Single Upstream Auth (behaves like old)", func(t *testing.T) {
		auth := setupAuthenticator()
		wsNamespace := "testns"
		wsName := "multi-ws-single"
		clientTokenValue := "client-token"
		clientTokenHeader := "X-Client-Token"

		mockUpstream1 := NewMockAuthServer(t)
		defer mockUpstream1.Close()
		mockUpstream1.ExpectedStatus = http.StatusOK
		mockUpstream1.ResponseHeaders.Set("U1-Care-Single", "ValSingle")

		upstreamServicesList := []cerberusv1alpha1.UpstreamHttpAuthService{
			{Address: mockUpstream1.URL, ReadTokenFrom: clientTokenHeader, WriteTokenTo: "U1-Auth", CareHeaders: []string{"U1-Care-Single"}, Timeout: 100},
		}
		// Use new helper: upstreamAuths is populated, deprecatedUpstreamAuth is nil
		wsEntry := createWebserviceEntry(wsNamespace, wsName, clientTokenHeader, upstreamServicesList, nil)
		(*auth.webservicesCache)[wsNamespace+"/"+wsName] = wsEntry
		(*auth.accessTokensCache)[clientTokenValue] = createTokenEntry(clientTokenValue, wsNamespace, wsName)

		req := &Request{
			Context: map[string]string{"webservice": wsName, "namespace": wsNamespace},
			Request: http.Request{Header: http.Header{clientTokenHeader: {clientTokenValue}}},
		}

		resp, err := auth.Check(context.Background(), req)

		assert.NoError(t, err)
		assert.True(t, resp.Allow)
		assert.Equal(t, string(CerberusReasonOK), resp.Response.Header.Get(CerberusHeaderReasonHeader))
		assert.Equal(t, "ValSingle", resp.Response.Header.Get("U1-Care-Single"))
		assert.True(t, mockUpstream1.Called, "Mock Upstream 1 should have been called")
	})

	t.Run("Token propagation where U2 reads token from U1 response, U1 does not have it in CareHeaders", func(t *testing.T) {
		auth := setupAuthenticator()
		wsNamespace := "testns"
		wsName := "multi-ws-token-prop-no-care"
		clientTokenValue := "initial-client-token"
		clientTokenHeader := "X-Client-Token"

		// Upstream 1: Gets client token, returns new token for U2 but NOT in its own CareHeaders for final response
		mockUpstream1 := NewMockAuthServer(t)
		defer mockUpstream1.Close()
		mockUpstream1.ExpectedStatus = http.StatusOK
		mockUpstream1.ExpectedRequestHeaders.Set("U1-Auth", clientTokenValue)
		mockUpstream1.ResponseHeaders.Set("Token-For-U2", "TokenFromU1ForU2")
		mockUpstream1.ResponseHeaders.Set("U1-OtherCare", "KeepThis")

		// Upstream 2: Gets token from U1.
		mockUpstream2 := NewMockAuthServer(t)
		defer mockUpstream2.Close()
		mockUpstream2.ExpectedStatus = http.StatusOK
		mockUpstream2.ExpectedRequestHeaders.Set("U2-Auth", "TokenFromU1ForU2")
		mockUpstream2.ResponseHeaders.Set("U2-Care", "U2Value")


		upstreamServicesList := []cerberusv1alpha1.UpstreamHttpAuthService{
			{
				Address:       mockUpstream1.URL,
				ReadTokenFrom: clientTokenHeader,
				WriteTokenTo:  "U1-Auth",
				CareHeaders:   []string{"U1-OtherCare"},
				Timeout:       100,
			},
			{
				Address:       mockUpstream2.URL,
				ReadTokenFrom: "Token-For-U2",
				WriteTokenTo:  "U2-Auth",
				CareHeaders:   []string{"U2-Care"},
				Timeout:       100,
			},
		}
		// Use new helper: upstreamAuths is populated, deprecatedUpstreamAuth is nil
		wsEntry := createWebserviceEntry(wsNamespace, wsName, clientTokenHeader, upstreamServicesList, nil)
		(*auth.webservicesCache)[wsNamespace+"/"+wsName] = wsEntry
		(*auth.accessTokensCache)[clientTokenValue] = createTokenEntry(clientTokenValue, wsNamespace, wsName)

		req := &Request{
			Context: map[string]string{"webservice": wsName, "namespace": wsNamespace},
			Request: http.Request{Header: http.Header{clientTokenHeader: {clientTokenValue}}},
		}

		resp, err := auth.Check(context.Background(), req)

		assert.NoError(t, err)
		assert.True(t, resp.Allow)
		assert.Equal(t, string(CerberusReasonOK), resp.Response.Header.Get(CerberusHeaderReasonHeader))

		// Check accumulated CareHeaders in final response
		assert.Equal(t, "KeepThis", resp.Response.Header.Get("U1-OtherCare"))
		assert.Equal(t, "U2Value", resp.Response.Header.Get("U2-Care"))
		assert.Empty(t, resp.Response.Header.Get("Token-For-U2"), "Token-For-U2 should not be in final response as it wasn't in U1.CareHeaders")

		assert.True(t, mockUpstream1.Called, "Mock Upstream 1 should be called")
		assert.True(t, mockUpstream2.Called, "Mock Upstream 2 should be called")
	})

	t.Run("Deprecated field only (success)", func(t *testing.T) {
		auth := setupAuthenticator()
		wsNamespace := "testns"
		wsName := "deprecated-ok"
		clientTokenValue := "client-token"
		clientTokenHeader := "X-Client-Token"

		mockUpstreamDeprecated := NewMockAuthServer(t)
		defer mockUpstreamDeprecated.Close()
		mockUpstreamDeprecated.ExpectedStatus = http.StatusOK
		mockUpstreamDeprecated.ExpectedRequestHeaders.Set("Deprecated-Auth", clientTokenValue)
		mockUpstreamDeprecated.ResponseHeaders.Set("Deprecated-Care", "DeprecatedVal")

		deprecatedService := &cerberusv1alpha1.UpstreamHttpAuthService{
			Address:       mockUpstreamDeprecated.URL,
			ReadTokenFrom: clientTokenHeader,
			WriteTokenTo:  "Deprecated-Auth",
			CareHeaders:   []string{"Deprecated-Care"},
			Timeout:       100,
		}
		// Use new helper: upstreamAuths is nil, deprecatedUpstreamAuth is populated
		wsEntry := createWebserviceEntry(wsNamespace, wsName, clientTokenHeader, nil, deprecatedService)
		(*auth.webservicesCache)[wsNamespace+"/"+wsName] = wsEntry
		(*auth.accessTokensCache)[clientTokenValue] = createTokenEntry(clientTokenValue, wsNamespace, wsName)

		req := &Request{
			Context: map[string]string{"webservice": wsName, "namespace": wsNamespace},
			Request: http.Request{Header: http.Header{clientTokenHeader: {clientTokenValue}}},
		}

		resp, err := auth.Check(context.Background(), req)

		assert.NoError(t, err)
		assert.True(t, resp.Allow)
		assert.Equal(t, string(CerberusReasonOK), resp.Response.Header.Get(CerberusHeaderReasonHeader))
		assert.Equal(t, "DeprecatedVal", resp.Response.Header.Get("Deprecated-Care"))
		assert.True(t, mockUpstreamDeprecated.Called, "Mock Deprecated Upstream should have been called")
	})

	t.Run("Deprecated field only (failure)", func(t *testing.T) {
		auth := setupAuthenticator()
		wsNamespace := "testns"
		wsName := "deprecated-fail"
		clientTokenValue := "client-token"
		clientTokenHeader := "X-Client-Token"

		mockUpstreamDeprecated := NewMockAuthServer(t)
		defer mockUpstreamDeprecated.Close()
		mockUpstreamDeprecated.ExpectedStatus = http.StatusUnauthorized // Fails

		deprecatedService := &cerberusv1alpha1.UpstreamHttpAuthService{
			Address:       mockUpstreamDeprecated.URL,
			ReadTokenFrom: clientTokenHeader,
			WriteTokenTo:  "Deprecated-Auth",
			Timeout:       100,
		}
		wsEntry := createWebserviceEntry(wsNamespace, wsName, clientTokenHeader, nil, deprecatedService)
		(*auth.webservicesCache)[wsNamespace+"/"+wsName] = wsEntry
		(*auth.accessTokensCache)[clientTokenValue] = createTokenEntry(clientTokenValue, wsNamespace, wsName)

		req := &Request{
			Context: map[string]string{"webservice": wsName, "namespace": wsNamespace},
			Request: http.Request{Header: http.Header{clientTokenHeader: {clientTokenValue}}},
		}

		resp, err := auth.Check(context.Background(), req)

		assert.NoError(t, err)
		assert.False(t, resp.Allow)
		assert.Equal(t, string(CerberusReasonUnauthorized), resp.Response.Header.Get(CerberusHeaderReasonHeader))
		assert.True(t, mockUpstreamDeprecated.Called, "Mock Deprecated Upstream should have been called")
	})

	t.Run("Field Precedence (UpstreamHttpAuths takes precedence)", func(t *testing.T) {
		auth := setupAuthenticator()
		wsNamespace := "testns"
		wsName := "precedence-test"
		clientTokenValue := "client-token"
		clientTokenHeader := "X-Client-Token"

		// UpstreamHttpAuths (plural, new field) - Service 1 & 2
		mockUpstreamNew1 := NewMockAuthServer(t)
		defer mockUpstreamNew1.Close()
		mockUpstreamNew1.ExpectedStatus = http.StatusOK
		mockUpstreamNew1.ResponseHeaders.Set("New-Care-1", "NewVal1")

		mockUpstreamNew2 := NewMockAuthServer(t)
		defer mockUpstreamNew2.Close()
		mockUpstreamNew2.ExpectedStatus = http.StatusOK
		mockUpstreamNew2.ResponseHeaders.Set("New-Care-2", "NewVal2")

		// UpstreamHttpAuth (singular, deprecated field) - Service 3
		mockUpstreamDeprecated := NewMockAuthServer(t)
		defer mockUpstreamDeprecated.Close()
		// This mock should not be called, so its properties don't strictly need setting unless for verification of non-call.

		newUpstreamServices := []cerberusv1alpha1.UpstreamHttpAuthService{
			{Address: mockUpstreamNew1.URL, ReadTokenFrom: clientTokenHeader, WriteTokenTo: "New1-Auth", CareHeaders: []string{"New-Care-1"}, Timeout: 100},
			{Address: mockUpstreamNew2.URL, ReadTokenFrom: clientTokenHeader, WriteTokenTo: "New2-Auth", CareHeaders: []string{"New-Care-2"}, Timeout: 100},
		}
		deprecatedService := &cerberusv1alpha1.UpstreamHttpAuthService{
			Address: mockUpstreamDeprecated.URL, ReadTokenFrom: clientTokenHeader, WriteTokenTo: "Deprecated-Auth", Timeout: 100,
		}

		// Populate both new (plural) and deprecated (singular) fields
		wsEntry := createWebserviceEntry(wsNamespace, wsName, clientTokenHeader, newUpstreamServices, deprecatedService)
		(*auth.webservicesCache)[wsNamespace+"/"+wsName] = wsEntry
		(*auth.accessTokensCache)[clientTokenValue] = createTokenEntry(clientTokenValue, wsNamespace, wsName)

		req := &Request{
			Context: map[string]string{"webservice": wsName, "namespace": wsNamespace},
			Request: http.Request{Header: http.Header{clientTokenHeader: {clientTokenValue}}},
		}

		resp, err := auth.Check(context.Background(), req)

		assert.NoError(t, err)
		assert.True(t, resp.Allow)
		assert.Equal(t, string(CerberusReasonOK), resp.Response.Header.Get(CerberusHeaderReasonHeader))
		assert.Equal(t, "NewVal1", resp.Response.Header.Get("New-Care-1"))
		assert.Equal(t, "NewVal2", resp.Response.Header.Get("New-Care-2"))
		assert.Empty(t, resp.Response.Header.Get("Deprecated-Care"), "Deprecated service header should not be present")

		assert.True(t, mockUpstreamNew1.Called, "Mock New Upstream 1 should be called")
		assert.True(t, mockUpstreamNew2.Called, "Mock New Upstream 2 should be called")
		assert.False(t, mockUpstreamDeprecated.Called, "Mock Deprecated Upstream should NOT be called")
	})

}


// MockAuthServer is a utility to mock an upstream authentication server.
// This should ideally be in a test utility file, but is included here for completeness
// if not already available in the testing environment.
// It is assumed a NewMockAuthServer() function exists that sets up an httptest.Server
// and returns a struct that includes the server URL and allows setting expectations.
// For the purpose of this diff, we'll assume its definition exists elsewhere
// (e.g. in a auth_test_utils.go or similar).
// If it doesn't, the following is a simplified version of what it might look like.

/*
type MockAuthServer struct {
	Server                 *httptest.Server
	ExpectedStatus         int
	ExpectedRequestHeaders map[string]string
	ResponseHeaders        map[string]string
	ExpectedBodyContains   string // If you need to check body
	ResponseBody           string // If you need to send a specific body
	Called                 bool
	t                      *testing.T
}

func NewMockAuthServer(t *testing.T) *MockAuthServer {
	mock := &MockAuthServer{
		ExpectedStatus: http.StatusOK, // Default to OK
		t:              t,
	}
	mock.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mock.Called = true
		// Check request headers
		for key, expectedValue := range mock.ExpectedRequestHeaders {
			actualValue := r.Header.Get(key)
			if actualValue != expectedValue {
				mock.t.Errorf("MockAuthServer: Header mismatch for %s: expected %s, got %s", key, expectedValue, actualValue)
			}
		}

		// Set response headers
		for key, value := range mock.ResponseHeaders {
			w.Header().Set(key, value)
		}

		w.WriteHeader(mock.ExpectedStatus)
		if mock.ResponseBody != "" {
			w.Write([]byte(mock.ResponseBody))
		}
	}))
	return mock
}

func (m *MockAuthServer) Close() {
	m.Server.Close()
}
*/
