package auth

import (
	"fmt"
	cerberusv1alpha1 "github.com/snapp-incubator/Cerberus/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"testing"

	"context"
	"github.com/stretchr/testify/assert"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var (
	ipAllowList     = generateIPAllowList(10000)    // Generate a large IP allow list
	domainAllowList = generateDomainAllowList(1000) // Generate a large domain allow list
	testIP          = "192.168.0.1"                 // Use a valid IP for testing
	testDomain      = "example.com"                 // Use a valid domain for testing
	tokenSecretRef  = generateTokenSecretRef()
	subjects        = generateSubjects(2)    // Generates ["subject-1", "subject-2"]
	webservices     = generateWebservices(2) // Generates ["webservice-1", "webservice-2"]

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

func generateTokenSecretRef() *corev1.LocalObjectReference {
	example := &corev1.LocalObjectReference{Name: "expmle"}
	return example
}

func generateSubjects(subjectCount int) []string {
	subjects := make([]string, subjectCount)

	for i := 0; i < subjectCount; i++ {
		subjects[i] = fmt.Sprintf("subject-%d", i+1)
	}

	return subjects
}

func generateWebservices(webserviceCount int) []string {
	webservices := make([]string, webserviceCount)

	for i := 0; i < webserviceCount; i++ {
		webservices[i] = fmt.Sprintf("webservice-%d", i+1)
	}

	return webservices
}

func BenchmarkCheckIPWithLargeInput(b *testing.B) {
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = CheckIP(testIP, ipAllowList)
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

func TestUpdateCache(t *testing.T) {
	fakeClient, authenticator := setupTestEnvironment(t)

	accessTokens := prepareAccessTokens(2)
	bindings := prepareWebserviceAccessBindings(2)
	webservices := prepareWebservices(2)
	secrets := prepareSecrets(2)

	createAccessTokens(t, fakeClient, accessTokens[0], accessTokens[1])
	createBindings(t, fakeClient, bindings[0], bindings[1])
	createWebservices(t, fakeClient, webservices[0], webservices[1])
	createSecrets(t, fakeClient, secrets[0], secrets[1])

	err := authenticator.UpdateCache(fakeClient, context.Background(), false)

	assert.NoError(t, err)

	assertCachesPopulated(t, authenticator)
}

func setupTestEnvironment(t *testing.T) (client.Client, *Authenticator) {
	// Initialize a Kubernetes client's scheme.
	scheme := runtime.NewScheme()

	// Register the custom resource type with the scheme.
	err := cerberusv1alpha1.AddToScheme(scheme)
	if err != nil {
		t.Fatalf("Failed to add cerberusv1alpha1 to scheme: %v", err)
	}

	err = v1.AddToScheme(scheme)
	if err != nil {
		t.Fatalf("Failed to add v1 to scheme: %v", err)
	}

	// Create a fake Kubernetes client using the registered scheme.
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	// Create an Authenticator instance.
	authenticator := &Authenticator{}

	return fakeClient, authenticator
}

func prepareAccessTokens(count int) []cerberusv1alpha1.AccessToken {
	// Create and prepare access tokens with unique names.
	accessTokens := make([]cerberusv1alpha1.AccessToken, count)
	for i := 0; i < count; i++ {
		tokenName := fmt.Sprintf("test-token-%d", i)
		accessTokens[i] = cerberusv1alpha1.AccessToken{
			ObjectMeta: metav1.ObjectMeta{Name: tokenName, Namespace: "default"},
			Spec: cerberusv1alpha1.AccessTokenSpec{
				State:           "",
				IpAllowList:     ipAllowList,
				DomainAllowList: domainAllowList,
				TokenSecretRef:  tokenSecretRef,
			},
		}
	}
	return accessTokens
}

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

func prepareWebservices(count int) []cerberusv1alpha1.WebService {
	// Create and prepare webservice resources with unique names.
	webservices := make([]cerberusv1alpha1.WebService, count)
	for i := 0; i < count; i++ {
		webserviceName := fmt.Sprintf("test-service-%d", i)
		webservices[i] = cerberusv1alpha1.WebService{
			ObjectMeta: metav1.ObjectMeta{Name: webserviceName, Namespace: "default"},
			Spec: cerberusv1alpha1.WebServiceSpec{
				LookupHeader: "X-Cerberus-Token",
				UpstreamHttpAuth: cerberusv1alpha1.UpstreamHttpAuthService{
					Address:       "http://example.com/auth",
					ReadTokenFrom: "Authorization",
					WriteTokenTo:  "X-Cerberus-Token",
				},
			},
		}
	}
	return webservices
}

func prepareSecrets(count int) []v1.Secret {
	// Create and prepare secrets with unique names.
	secrets := make([]v1.Secret, count)
	for i := 0; i < count; i++ {
		secretName := fmt.Sprintf("test-secret-%d", i)
		secrets[i] = v1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: "default"},
			Data: map[string][]byte{
				"token": []byte("test-token-value"),
			},
		}
	}
	return secrets
}

//func createResources(t *testing.T, fakeClient client.Client, resources ...client.Object) {
//	ctx := context.Background()
//	for _, resource := range resources {
//		assert.NoError(t, fakeClient.Create(ctx, resource))
//	}
//}

func createAccessTokens(t *testing.T, fakeClient client.Client, accessTokens ...cerberusv1alpha1.AccessToken) {
	ctx := context.Background()
	for _, token := range accessTokens {
		assert.NoError(t, fakeClient.Create(ctx, &token))
	}
}

func createBindings(t *testing.T, fakeClient client.Client, bindings ...cerberusv1alpha1.WebserviceAccessBinding) {
	ctx := context.Background()
	for _, binding := range bindings {
		assert.NoError(t, fakeClient.Create(ctx, &binding))
	}
}

func createWebservices(t *testing.T, fakeClient client.Client, webservices ...cerberusv1alpha1.WebService) {
	ctx := context.Background()
	for _, service := range webservices {
		assert.NoError(t, fakeClient.Create(ctx, &service))
	}
}

func createSecrets(t *testing.T, fakeClient client.Client, secrets ...v1.Secret) {
	ctx := context.Background()
	for _, secret := range secrets {
		assert.NoError(t, fakeClient.Create(ctx, &secret))
	}
}

func assertCachesPopulated(t *testing.T, authenticator *Authenticator) {
	authenticator.cacheLock.RLock()
	defer authenticator.cacheLock.RUnlock()

	//assert.NotEmpty(t, authenticator.accessCache)
	assert.NotEmpty(t, authenticator.servicesCache)
}
