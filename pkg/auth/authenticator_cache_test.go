package auth

import (
	"fmt"
	"testing"

	"github.com/go-logr/logr"
	"github.com/snapp-incubator/Cerberus/api/v1alpha1"
	"github.com/snapp-incubator/Cerberus/pkg/testutils"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type Namer interface {
	GetName() string
	GetNamespace() string
}

func localName(meta Namer) string {
	return fmt.Sprintf("%s/%s", meta.GetNamespace(), meta.GetName())
}
func TestEncodeLocalName(t *testing.T) {
	type testCase struct {
		namespace string
		name      string
		expected  string
	}

	testCases := []testCase{
		{
			namespace: "example",
			name:      "token1",
			expected:  "example/token1",
		},
		{
			namespace: "namespace",
			name:      "token2",
			expected:  "namespace/token2",
		},
	}

	for _, tc := range testCases {
		entry := AccessTokensCacheEntry{}
		entry.Name = tc.name
		entry.Namespace = tc.namespace
		actual := encodeLocalName(entry)
		if actual != tc.expected {
			t.Errorf("encodeLocalName(%v) = %s; expected %s", entry, actual, tc.expected)
		}
	}
}

func TestDecodeLocalName(t *testing.T) {
	// Test cases
	tests := []struct {
		input             string
		expectedName      string
		expectedNamespace string
	}{
		{
			input:             "example/token1",
			expectedName:      "example",
			expectedNamespace: "token1",
		},
		{
			input:             "namespace/token2",
			expectedName:      "namespace",
			expectedNamespace: "token2",
		},
		{
			input:             "token3",
			expectedName:      "token3",
			expectedNamespace: "",
		},
	}

	// Iterate through test cases
	for _, test := range tests {
		actualName, actualNamespace := decodeLocalName(test.input)
		if actualName != test.expectedName || actualNamespace != test.expectedNamespace {
			t.Errorf("decodeLocalName(%s) = (%s, %s); expected (%s, %s)", test.input, actualName, actualNamespace, test.expectedName, test.expectedNamespace)
		}
	}
}

func TestBuildNewWebservicesCache(t *testing.T) {
	// Create instances of mocked logger, AccessTokensCache, and WebservicesCache
	sink := testutils.TestLogSink{}
	// Create an instance of the Authenticator with mocked dependencies
	auth := &Authenticator{
		logger: logr.New(&sink),
		// accessTokensCache: mockAccessTokensCache,
		// webservicesCache:  mockWebservicesCache,
	}

	// Create and prepare mock data for Kubernetes resources.
	// accessTokens := prepareAccessTokens(2)
	webservices := &v1alpha1.WebServiceList{
		Items: prepareWebservices(2),
	}
	noNamespaceService := v1alpha1.WebService{
		ObjectMeta: v1.ObjectMeta{
			Name: "nonamespace",
		},
	}
	webservices.Items = append(webservices.Items, noNamespaceService)
	bindings := &v1alpha1.WebserviceAccessBindingList{
		Items: prepareWebserviceAccessBindings(2),
	}

	newWebservicesCache := auth.buildNewWebservicesCache(webservices, bindings)

	assert.Equal(t, "info", sink.Logs[0].Type)
	assert.Equal(t, "webservice namespace is empty", sink.Logs[0].Message)
	assert.Equal(t, noNamespaceService.Name, sink.Logs[0].KeyValues["webservice"])

	bindingLogs := sink.Logs[1:]
	for i, binding := range bindings.Items {
		log := bindingLogs[i]
		assert.Equal(t, "info", log.Type)
		assert.Equal(t, "ignored some webservices over binding", log.Message)
		assert.Equal(t, binding.Namespace+"/"+binding.Name, log.KeyValues["binding"])
	}

	assert.Len(t, *newWebservicesCache, 2)
}

func TestAllowNamespaceAndAdd(t *testing.T) {
	wsce := WebservicesCacheEntry{
		allowedNamespacesCache: make(AllowedNamespacesCache),
	}
	wsce.allowedNamespacesCache["x"] = struct{}{}
	wsce.allowedNamespacesCache["y"] = struct{}{}

	// Check adding new namespace directly to the cache interface
	wsce.allowedNamespacesCache.add("test1")
	assert.Contains(t, wsce.allowedNamespacesCache, "test1")
	assert.Len(t, wsce.allowedNamespacesCache, 3)

	// Check adding new namespace with allowNamespace
	wsce.allowNamespace("test2")
	assert.Contains(t, wsce.allowedNamespacesCache, "test2")
	assert.Len(t, wsce.allowedNamespacesCache, 4)

	// Adding x again should do nothing
	wsce.allowNamespace("x")
	wsce.allowedNamespacesCache.add("x")
	assert.Len(t, wsce.allowedNamespacesCache, 4)

}

func TestCheckAccessFrom(t *testing.T) {
	wsce := WebservicesCacheEntry{
		allowedNamespacesCache: make(AllowedNamespacesCache),
	}
	wsce.allowedNamespacesCache["x"] = struct{}{}
	wsce.allowedNamespacesCache["y"] = struct{}{}

	assert.True(t, wsce.checkAccessFrom("x"))
	assert.False(t, wsce.checkAccessFrom("z"))
}

func TestGetSecretRawTokenMap(t *testing.T) {
	// Test case 1: Secrets list is empty
	emptySecrets := &corev1.SecretList{}
	emptyMap := getSecretRawTokenMap(emptySecrets)
	assert.Empty(t, emptyMap, "Result map should be empty for an empty secrets list")

	// Test case 2: Secrets list with one secret containing "token" field
	secretWithData := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "secret1"},
		Data:       map[string][]byte{"token": []byte("my-secret-token")},
	}
	secretsList := &corev1.SecretList{Items: []corev1.Secret{secretWithData}}
	resultMap := getSecretRawTokenMap(secretsList)
	assert.Len(t, resultMap, 1, "Result map should contain one entry")
	assert.Equal(t, "my-secret-token", resultMap["secret1"], "Token value should be 'my-secret-token'")

	// Test case 3: Secrets list with one secret missing "token" field
	secretWithoutToken := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "secret2"},
		Data:       map[string][]byte{},
	}
	secretsList.Items = append(secretsList.Items, secretWithoutToken)
	resultMap = getSecretRawTokenMap(secretsList)
	assert.Len(t, resultMap, 2, "Result map should contain two entries")
	assert.Equal(t, "my-secret-token", resultMap["secret1"], "Token value should be 'my-secret-token'")
	assert.Equal(t, "token-field-not-found", resultMap["secret2"], "Token value should be 'token-field-not-found'")
}

func TestWebservicesCache_AllowWebserviceCallsFromNamespace(t *testing.T) {
	// Create a mock WebservicesCache
	cache := make(WebservicesCache)
	cacheEntry := WebservicesCacheEntry{
		WebService:             v1alpha1.WebService{},
		allowedNamespacesCache: make(AllowedNamespacesCache),
	}
	cacheEntry.allowedNamespacesCache["namespace1"] = struct{}{}
	cache["webservice1"] = cacheEntry

	// Test case 1: Allow namespace access to the webservice
	err := cache.allowWebserviceCallsFromNamespace("webservice1", "namespace1")
	assert.NoError(t, err, "No error should occur")
	assert.True(t, cache["webservice1"].checkAccessFrom("namespace1"), "Namespace should have access to the webservice")

	// Test case 2: Try to allow access for a non-existent webservice
	err = cache.allowWebserviceCallsFromNamespace("nonexistentwebservice", "namespace1")
	assert.Error(t, err, "Error should occur for nonexistent webservice")
	assert.EqualError(t, err, "webservice not found in webservices cache", "Error message should indicate webservice not found")
}

func TestWebservicesCache_validateWebservice(t *testing.T) {
	// Mocking a WebservicesCacheEntry
	wsc := make(WebservicesCache)
	ws := v1alpha1.WebService{}
	wsc[ws.LocalName()] = WebservicesCacheEntry{
		WebService:             ws,
		allowedNamespacesCache: make(AllowedNamespacesCache),
	}
	assert.NoError(t, wsc.validateWebservice(ws.LocalName()))
	assert.ErrorContains(t, wsc.validateWebservice("not-defined"), "webservice not found in webservices cache")
}

func TestWebservicesCacheEntry_checkAccessFrom(t *testing.T) {
	// Mocking a WebservicesCacheEntry with allowed namespaces
	wse := WebservicesCacheEntry{
		WebService:             v1alpha1.WebService{},
		allowedNamespacesCache: make(AllowedNamespacesCache),
	}

	assert.False(t, wse.checkAccessFrom("x"))

	wse.allowedNamespacesCache["x"] = struct{}{}
	assert.True(t, wse.checkAccessFrom("x"))
}

func TestWebservicesCache_CheckAccess(t *testing.T) {
	// Create a mock WebservicesCache
	cache := make(WebservicesCache)
	cacheEntry := WebservicesCacheEntry{
		WebService:             v1alpha1.WebService{},
		allowedNamespacesCache: make(AllowedNamespacesCache),
	}
	cacheEntry.allowedNamespacesCache["namespace1"] = struct{}{}
	cache["webservice1"] = cacheEntry

	// Test case 1: Namespace is allowed
	allowed, err := cache.checkAccess("webservice1", "namespace1")
	assert.NoError(t, err, "No error should occur")
	assert.True(t, allowed, "Namespace should have access to the webservice")

	// Test case 2: Namespace is not allowed
	allowed, err = cache.checkAccess("webservice1", "namespace2")
	assert.NoError(t, err, "No error should occur")
	assert.False(t, allowed, "Namespace should not have access to the webservice")

	// Test case 3: Webservice not found
	_, err = cache.checkAccess("nonexistentwebservice", "namespace1")
	assert.Error(t, err, "Error should occur for nonexistent webservice")
	assert.EqualError(t, err, "webservice not found in webservices cache", "Error message should indicate webservice not found")
}

func TestWebservicesCache_ReadWebservice(t *testing.T) {
	cache := make(WebservicesCache)
	cacheEntry := WebservicesCacheEntry{
		WebService: v1alpha1.WebService{
			ObjectMeta: v1.ObjectMeta{
				Name:      "webservice1",
				Namespace: "does not matter",
			},
		},
		allowedNamespacesCache: make(AllowedNamespacesCache),
	}
	cache["webservice1"] = cacheEntry

	value, ok := cache.ReadWebservice("webservice1")
	assert.True(t, ok)
	assert.Equal(t, cacheEntry, value)

	_, ok = cache.ReadWebservice("webservice2")
	assert.False(t, ok)
}

func TestAccessTokensCache_ReadAccessToken(t *testing.T) {
	cache := make(AccessTokensCache)
	cacheEntry := AccessTokensCacheEntry{
		AccessToken: v1alpha1.AccessToken{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "token1",
				Namespace: "random-name",
			},
		},
		allowedWebservicesCache: make(AllowedWebservicesCache),
	}
	cache["token1"] = cacheEntry

	value, ok := cache.ReadAccessToken("token1")
	assert.True(t, ok)
	assert.Equal(t, cacheEntry, value)

	_, ok = cache.ReadAccessToken("token2")
	assert.False(t, ok)
}

func TestAccessTokensCacheEntry_TestAccess(t *testing.T) {
	cacheEntry := AccessTokensCacheEntry{
		AccessToken: v1alpha1.AccessToken{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "token1",
				Namespace: "random-name",
			},
		},
		allowedWebservicesCache: make(AllowedWebservicesCache),
	}
	cacheEntry.allowedWebservicesCache["webservice1"] = struct{}{}

	assert.True(t, cacheEntry.TestAccess("webservice1"))
	assert.False(t, cacheEntry.TestAccess("webservice2"))

}

func TestAccessTokensCache_buildAllowedWebservicesCache(t *testing.T) {
	cache := make(WebservicesCache)
	cacheEntry1 := WebservicesCacheEntry{
		WebService: v1alpha1.WebService{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "webservice1",
				Namespace: "namespace1",
			},
		},
		allowedNamespacesCache: AllowedNamespacesCache{"namespace1": struct{}{}},
	}
	cacheEntry2 := WebservicesCacheEntry{
		WebService: v1alpha1.WebService{
			ObjectMeta: metav1.ObjectMeta{
				Name: "webservice2",
			},
		},
		allowedNamespacesCache: AllowedNamespacesCache{"namespace1": struct{}{}},
	}
	cache[cacheEntry1.WebService.LocalName()] = cacheEntry1
	cache["namespace1/"+cacheEntry2.WebService.Name] = cacheEntry2

	// Create a mock AccessTokensCacheEntry
	accessTokenEntry1 := AccessTokensCacheEntry{
		AccessToken: v1alpha1.AccessToken{
			ObjectMeta: v1.ObjectMeta{
				Name:      "token1",
				Namespace: "namespace1",
			},
			Spec: v1alpha1.AccessTokenSpec{
				AllowedWebservices: []*v1alpha1.WebserviceReference{
					{
						Namespace: "namespace1",
						Name:      "webservice1",
					},
					{
						Namespace: "namespace2", // Invalid namespace
						Name:      "webservice2",
					},
				},
			},
		},
		allowedWebservicesCache: make(AllowedWebservicesCache),
	}
	accessTokenEntry2 := AccessTokensCacheEntry{
		AccessToken: v1alpha1.AccessToken{
			ObjectMeta: v1.ObjectMeta{
				Name:      "token2",
				Namespace: "namespace1",
			},
			Spec: v1alpha1.AccessTokenSpec{
				AllowedWebservices: []*v1alpha1.WebserviceReference{
					{
						Namespace: "namespace1",
						Name:      "webservice2",
					},
					{
						Namespace: "namespace3", // Invalid namespace
						Name:      "webservice2",
					},
				},
			},
		},
		allowedWebservicesCache: make(AllowedWebservicesCache),
	}
	tokenCache := make(AccessTokensCache)

	tokenCache["token1"] = accessTokenEntry1
	tokenCache["token2"] = accessTokenEntry2

	// Checking ignores
	ignored := tokenCache.buildAllowedWebservicesCache(&cache)
	assert.Contains(t, ignored, localName(&accessTokenEntry1))
	assert.Contains(t, ignored, localName(&accessTokenEntry2))
	assert.Contains(t, ignored[localName(&accessTokenEntry1)], accessTokenEntry1.Spec.AllowedWebservices[1])
	assert.Contains(t, ignored[localName(&accessTokenEntry2)], accessTokenEntry2.Spec.AllowedWebservices[1])

	// Checking token cache allowedWebservicesCache
	expectedWebservice1 := accessTokenEntry1.Spec.AllowedWebservices[0]
	expectedWebservice2 := accessTokenEntry2.Spec.AllowedWebservices[0]
	assert.Contains(t, tokenCache, "token1")
	assert.Contains(t, tokenCache["token1"].allowedWebservicesCache, expectedWebservice1.LocalName())
	assert.Contains(t, tokenCache, "token2")
	assert.Contains(t, tokenCache["token2"].allowedWebservicesCache, expectedWebservice2.LocalName())
}

func TestAccessTokensCacheEntry_buildAllowedWebservicesCache(t *testing.T) {
	// Create a mock WebservicesCache
	cache := make(WebservicesCache)
	cacheEntry1 := WebservicesCacheEntry{
		WebService: v1alpha1.WebService{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "webservice1",
				Namespace: "namespace1",
			},
		},
		allowedNamespacesCache: AllowedNamespacesCache{"namespace1": struct{}{}},
	}
	cacheEntry2 := WebservicesCacheEntry{
		WebService: v1alpha1.WebService{
			ObjectMeta: metav1.ObjectMeta{
				Name: "webservice2",
			},
		},
		allowedNamespacesCache: AllowedNamespacesCache{"namespace1": struct{}{}},
	}
	cache[cacheEntry1.WebService.LocalName()] = cacheEntry1
	cache["namespace1/"+cacheEntry2.WebService.Name] = cacheEntry2

	// Create a mock AccessTokensCacheEntry
	accessToken := AccessTokensCacheEntry{
		AccessToken: v1alpha1.AccessToken{
			ObjectMeta: v1.ObjectMeta{
				Name:      "token1",
				Namespace: "namespace1",
			},
			Spec: v1alpha1.AccessTokenSpec{
				AllowedWebservices: []*v1alpha1.WebserviceReference{
					{
						Namespace: "namespace1",
						Name:      "webservice1",
					},
					{
						Namespace: "", // Empty namespace should default to AccessToken's namespace
						Name:      "webservice2",
					},
					{
						Namespace: "namespace2", // Invalid namespace
						Name:      "webservice2",
					},
				},
			},
		},
		allowedWebservicesCache: make(AllowedWebservicesCache),
	}

	// Call the function
	ignoredEntries := accessToken.buildAllowedWebservicesCache(&cache)

	// Check cache
	assert.Len(t, accessToken.allowedWebservicesCache, 2)
	assert.Contains(t, accessToken.allowedWebservicesCache,
		cacheEntry1.LocalName())

	// Check if it adds default namespace with tokens namespace
	assert.Contains(t, accessToken.allowedWebservicesCache,
		fmt.Sprintf("%s/%s", accessToken.Namespace, cacheEntry2.Name))

	// Check results
	assert.Len(t, ignoredEntries, 1, "There should be one ignored entry")
	assert.Equal(t, "namespace2", ignoredEntries[0].Namespace,
		"The ignored entry should have namespace 'namespace2'")
	fmt.Println(accessToken.allowedWebservicesCache)

}
