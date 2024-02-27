package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	cerberusv1alpha1 "github.com/snapp-incubator/Cerberus/api/v1alpha1"
	"github.com/stretchr/testify/assert"
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
	reason := validateUpstreamAuthRequest(service)
	assert.Equal(t, CerberusReasonTargetAuthTokenEmpty, reason, "Expected target auth token empty")

	// Test case 2: WriteTokenTo is empty
	service = WebservicesCacheEntry{}
	service.Spec.UpstreamHttpAuth.ReadTokenFrom = "token"
	service.Spec.UpstreamHttpAuth.WriteTokenTo = ""
	reason = validateUpstreamAuthRequest(service)
	assert.Equal(t, CerberusReasonTargetAuthTokenEmpty, reason, "Expected target auth token empty")

	// Test case 3: ReadTokenFrom is empty
	service = WebservicesCacheEntry{}
	service.Spec.UpstreamHttpAuth.ReadTokenFrom = ""
	service.Spec.UpstreamHttpAuth.WriteTokenTo = "token"
	reason = validateUpstreamAuthRequest(service)
	assert.Equal(t, CerberusReasonTargetAuthTokenEmpty, reason, "Expected target auth token empty")

	// Test case 4: Address is invalid
	service = WebservicesCacheEntry{}
	service.Spec.UpstreamHttpAuth.ReadTokenFrom = "token"
	service.Spec.UpstreamHttpAuth.WriteTokenTo = "token"
	service.Spec.UpstreamHttpAuth.Address = "not a valid URL"
	reason = validateUpstreamAuthRequest(service)
	assert.Equal(t, CerberusReasonInvalidUpstreamAddress, reason, "Expected invalid upstream address")

	// Test case 5: Everything is valid
	service = WebservicesCacheEntry{}
	service.Spec.UpstreamHttpAuth.ReadTokenFrom = "token"
	service.Spec.UpstreamHttpAuth.WriteTokenTo = "token"
	service.Spec.UpstreamHttpAuth.Address = "http://example.com"
	reason = validateUpstreamAuthRequest(service)
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

	actualReq, actualErr := setupUpstreamAuthRequest(upstreamAuth, request)
	assert.NoError(t, actualErr, "No error should occur")
	assert.Equal(t, expectedReq.URL.String(), actualReq.URL.String(), "Request URL should match")
	assert.Equal(t, expectedReq.Header, actualReq.Header, "Request headers should match")

	// Test case 2: Error from http.NewRequest
	upstreamAuth = &cerberusv1alpha1.UpstreamHttpAuthService{
		Address: ":",
	} // Empty service
	request = &Request{}

	actualReq, actualErr = setupUpstreamAuthRequest(upstreamAuth, request)
	assert.Nil(t, actualReq, "Request should be nil when there is an error")
	assert.Error(t, actualErr, "Error should occur when service is empty")
}
