package auth

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/snapp-incubator/Cerberus/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// AccessTokensCache is where Authenticator holds its authentication data,
// under the hood it is a Map from RawTokens to some information about
// AccessToken, see AccessCacheEntry for more information
type AccessTokensCache map[string]AccessTokensCacheEntry

// WebservicesCache will hold information about all listed and suppoerted
// Webservices by the Authenticator
type WebservicesCache map[string]WebservicesCacheEntry

// AccessTokensCacheEntry will hold all datas included in AccessToken manifest,
// and it also holds a map[string]struct{} which holds name of Webservices
// which the given token has access to.
type AccessTokensCacheEntry struct {
	v1alpha1.AccessToken
	allowedWebservicesCache AllowedWebservicesCache
}

// AllowedWebserviceCache will hold which Webservices in which Namespaces does the AccessToken
// has access to (e.g AccessCache["ns-123/wsvc-123"] is present
// if the corresponding AccessToken has access to <wsvc-123> in namespace <ns-123>)
type AllowedWebservicesCache map[string]struct{}

// WebservicesCacheEntry will hold all datas included in Webservice manifest
type WebservicesCacheEntry struct {
	v1alpha1.WebService
	allowedNamespacesCache AllowedNamespacesCache
}

// AllowedNamespacesCache will hold all namespaces that are allowed to call this webservice
type AllowedNamespacesCache map[string]struct{}

// UpdateCache will accuire a lock on other UpdateCaches and will start to recreate
// the entire AccessCache and WebserviceCaches (which contains all authentication information)
func (a *Authenticator) UpdateCache(c client.Client, ctx context.Context, readOnly bool) (err error) {
	a.logger.Info("updated cache triggered")
	cacheUpdateCount.Inc()
	cacheUpdateStartTime := time.Now()
	defer func() {
		cacheUpdateLatency.Observe(time.Since(cacheUpdateStartTime).Seconds())
	}()

	a.updateLock.Lock()
	defer a.updateLock.Unlock()

	tokens := &v1alpha1.AccessTokenList{}
	err = retrieveObjects(tokens, c, ctx)
	if err != nil {
		return
	}

	secrets := &corev1.SecretList{}
	err = retrieveObjects(secrets, c, ctx)
	if err != nil {
		return
	}

	bindings := &v1alpha1.WebserviceAccessBindingList{}
	err = retrieveObjects(bindings, c, ctx)
	if err != nil {
		return
	}

	webservices := &v1alpha1.WebServiceList{}
	err = retrieveObjects(webservices, c, ctx)
	if err != nil {
		return
	}

	newWebservicesCache := a.buildNewWebservicesCache(webservices, bindings)
	newAccessCache := a.buildNewAccessTokensCache(tokens, secrets, newWebservicesCache)

	cacheWriteLockRequestStartTime := time.Now()
	a.cacheLock.Lock()
	cacheWriteLockWaitingTime.Observe(time.Since(cacheWriteLockRequestStartTime).Seconds())
	defer a.cacheLock.Unlock()

	cacheWriteStartTime := time.Now()
	a.accessTokensCache = newAccessCache
	a.webservicesCache = newWebservicesCache
	cacheWriteTime.Observe(time.Since(cacheWriteStartTime).Seconds())
	a.logger.Info("updated cache successfully")
	return nil
}

// retrieveObjects is a generic function which will list all the Objects matching given type
// from API Server using given k8s client and ctx and returns a pointer to a list of them
func retrieveObjects(
	l client.ObjectList,
	c client.Client,
	ctx context.Context,
	listOpts ...*client.ListOptions,
) error {
	t := time.Now()
	metricsLabel := reflect.TypeOf(l).Elem().String()
	err := c.List(ctx, l)
	fetchObjectListLatency.With(AddKindLabel(nil, metricsLabel)).Observe(time.Since(t).Seconds())
	return err
}

// buildNewWebservicesCache creates WebservicesCacheEntry for each webservice and then it
// fills allowedNamespaces for every given webservice over given bindings
// later this allowedNamespaces will be used in building/verifing AccessTokensCache
func (a *Authenticator) buildNewWebservicesCache(
	webservices *v1alpha1.WebServiceList,
	bindings *v1alpha1.WebserviceAccessBindingList,
) *WebservicesCache {
	newWebservicesCache := make(WebservicesCache)
	for _, webservice := range webservices.Items {
		if webservice.Namespace == "" {
			a.logger.Info("webservice namespace is empty",
				"webservice", webservice.Name,
			)
			continue
		}
		newWebservicesCache[webservice.LocalName()] = WebservicesCacheEntry{
			WebService:             webservice,
			allowedNamespacesCache: make(AllowedNamespacesCache),
		}
	}
	webserviceCacheEntries.Set(float64(len(newWebservicesCache)))

	ignoredBindings := newWebservicesCache.buildAllowedNamespacesCache(bindings)
	if len(ignoredBindings) > 0 {
		for name, wsvcs := range ignoredBindings {
			a.logger.Info("ignored some webservices over binding",
				"binding", name, "webservices", strings.Join(wsvcs, ","),
			)
		}
	}

	a.logger.Info("webservice access cache built successfully", "len", len(newWebservicesCache))

	for _, entry := range newWebservicesCache {
		a.logger.Info("webservice stored", "name", entry.Name, "allowedNamespaces", entry.allowedNamespacesCache)
	}

	return &newWebservicesCache
}

// buildNewAccessTokensCache creates AccessTokensCache and validated given access for each AccessToken
func (a *Authenticator) buildNewAccessTokensCache(
	tokens *v1alpha1.AccessTokenList,
	secrets *corev1.SecretList,
	newWebservicesCache *WebservicesCache,
) *AccessTokensCache {
	secretValues := getSecretRawTokenMap(secrets) // Secret.Name -> Secret.Data.token
	newAccessTokensCache := make(AccessTokensCache)

	for _, token := range tokens.Items {
		tokenInfoLogger := a.logger.WithValues("accesstoken", token.Name, "namespace", token.Namespace)
		if strings.Contains(token.Name, ".") {
			// TODO: update AccessToken status and report the error
			tokenInfoLogger.Info("dot character is not allowed in AccessToken name")
			continue
		}
		if strings.Contains(token.Namespace, ".") {
			// TODO: update AccessToken status and report the error
			tokenInfoLogger.Info("dot character is not allowed in AccessToken namespace")
			continue
		}

		tokenRawValue, ok := secretValues[token.Namespace+"."+token.Name]
		if !ok {
			tokenInfoLogger.Info("unable to find secret for accesstoken")
			continue
		}
		if tokenRawValue == "token-field-not-found" {
			tokenInfoLogger.Info("corresponding secret for accesstoken does not contain token field")
			continue
		}

		newAccessTokensCache[tokenRawValue] = AccessTokensCacheEntry{
			AccessToken:             token,
			allowedWebservicesCache: make(AllowedWebservicesCache),
		}
	}
	accessCacheEntries.Set(float64(len(newAccessTokensCache)))

	ignoredRequestedAccesses := newAccessTokensCache.buildAllowedWebservicesCache(newWebservicesCache)
	for at, ignoredWebservices := range ignoredRequestedAccesses {
		result := make([]string, 0)
		for _, wr := range ignoredWebservices {
			result = append(result, wr.LocalName())
		}
		name, namespace := decodeLocalName(at)
		if len(result) > 0 {
			a.logger.Info("some allowed webservices for token are ignored",
				"accesstoken", name, "namespace", namespace, "ignored", strings.Join(result, ","),
			)
		}
	}

	a.logger.Info("access token cache built successfully", "len", len(newAccessTokensCache))

	for _, entry := range newAccessTokensCache {
		a.logger.Info("webservice stored", "name", entry.Name, "allowedWebservices", entry.allowedWebservicesCache)
	}

	return &newAccessTokensCache
}

// buildAllowedNamespacesCache builds allowedNamespacesCache for the WebservicesCache over given bindings
// it also allows requests from same namespace to webservice
func (c *WebservicesCache) buildAllowedNamespacesCache(bindings *v1alpha1.WebserviceAccessBindingList) map[string][]string {
	for _, wsvc := range *c {
		wsvc.allowNamespace(wsvc.Namespace)
	}

	ignoredBindings := make(map[string][]string)
	for _, binding := range bindings.Items {
		for _, wsvc := range binding.Spec.Webservices {
			for _, ns := range binding.Spec.Subjects {
				err := c.allowWebserviceCallsFromNamespace(wsvc.LocalName(binding.Namespace), ns)
				if err != nil {
					eb := binding.Namespace + "/" + binding.Name
					if _, ok := ignoredBindings[eb]; !ok {
						ignoredBindings[eb] = make([]string, 0)
					}
					ignoredBindings[eb] = append(ignoredBindings[eb], wsvc.LocalName(binding.Namespace))
				}
			}
		}
	}
	return ignoredBindings
}

// allowWebserviceCallsFromNamespace adds given namespace to allowed namespaces for given webservice
// (it adds namespace to webservice.allowedNamespacesCache)
// will return error if wsvc not exists in cache webservices
func (c *WebservicesCache) allowWebserviceCallsFromNamespace(wsvc string, ns string) error {
	if err := c.validateWebservice(wsvc); err != nil {
		return err
	}
	(*c)[wsvc].allowNamespace(ns)
	return nil
}

// checkAccess returns true if given namespace has access to given webservice
func (c *WebservicesCache) checkAccess(wsvc string, ns string) (bool, error) {
	if err := c.validateWebservice(wsvc); err != nil {
		return false, err
	}
	return (*c)[wsvc].checkAccessFrom(ns), nil
}

// validateWebservice raises a proper error if wsvc is not present in cache
func (c *WebservicesCache) validateWebservice(wsvc string) (err error) {
	if _, ok := (*c)[wsvc]; !ok {
		err = fmt.Errorf("webservice not found in webservices cache")
	}
	return
}

// allowNamespace adds given namespace to given cache entry for a webservice
func (c WebservicesCacheEntry) allowNamespace(ns string) {
	c.allowedNamespacesCache.add(ns)
}

// checkAccessFrom returns true if given namespace has access to correspondig webservice
func (c WebservicesCacheEntry) checkAccessFrom(ns string) bool {
	_, ok := c.allowedNamespacesCache[ns]
	return ok
}

// add inserts given namespace as a key into underlying map behind AllowedNamespacesCache
func (c AllowedNamespacesCache) add(ns string) {
	c[ns] = struct{}{}
}

// getSecretRawTokenMap converts a secret list to a map from secret name to it's
// token field value for faster access to token values by secret name
func getSecretRawTokenMap(secrets *corev1.SecretList) map[string]string {
	result := make(map[string]string)
	for _, secret := range secrets.Items {
		if t, ok := secret.Data["token"]; ok {
			result[secret.Name] = string(t)
		} else {
			result[secret.Name] = "token-field-not-found"
		}
	}
	return result
}

// buildAllowedWebservicesCache builds actual access cache for each token and returns all ignored entries
// per accesstoken names encoded in [Namespace/Name]->[]*wsvcRefs model
func (c *AccessTokensCache) buildAllowedWebservicesCache(newWebservicesCache *WebservicesCache) map[string][]*v1alpha1.WebserviceReference {
	ignoredEntries := make(map[string][]*v1alpha1.WebserviceReference)
	for tRaw, token := range *c {
		ignoredEntriesForToken := (*c)[tRaw].buildAllowedWebservicesCache(newWebservicesCache)
		ignoredEntries[encodeLocalName(token)] = ignoredEntriesForToken
	}
	return ignoredEntries
}

// buildAllowedWebservicesCache adds valid AllowedWebservices from AccessToken.Spec to actual cache
// and returns ignores WebserviceReferences
func (t AccessTokensCacheEntry) buildAllowedWebservicesCache(newWebservicesCache *WebservicesCache) []*v1alpha1.WebserviceReference {
	ignoredEntries := make([]*v1alpha1.WebserviceReference, 0)
	for _, webserviceRef := range t.Spec.AllowedWebservices {
		if webserviceRef.Namespace == "" {
			webserviceRef.Namespace = t.Namespace
		}

		if ok, err := newWebservicesCache.checkAccess(
			webserviceRef.LocalName(), t.Namespace,
		); !ok || err != nil {
			ignoredEntries = append(ignoredEntries, webserviceRef)
			continue
		}
		t.allowedWebservicesCache.add(webserviceRef.LocalName())
	}
	return ignoredEntries
}

// add inserted a local webservice name to actual access cache for a token
func (c AllowedWebservicesCache) add(wsvc string) {
	c[wsvc] = struct{}{}
}

// encodeAccessTokenLocalName encodes AccessTokensCacheEntry name and namespace into a single string
// (concats them with a "/" in between). use decodeAccessTokenLocalName to retrive Name and Namespace
// mainly used for trace and log returning in functions
func encodeLocalName(at AccessTokensCacheEntry) string {
	return at.Namespace + "/" + at.Name
}

// decodeAccessTokenLocalName decodes encodeAccessTokenLocalName result into corresponding Name and Namespace
func decodeLocalName(at string) (name, namespace string) {
	s := strings.Split(at, "/")
	name = s[0]
	if len(s) > 1 {
		namespace = s[1]
	}
	return
}

// ReadWebservice returns cache entry for service name
func (c *WebservicesCache) ReadWebservice(wsvc string) (WebservicesCacheEntry, bool) {
	r, ok := (*c)[wsvc]
	return r, ok
}

// ReadAccessToken
func (c *AccessTokensCache) ReadAccessToken(rawToken string) (AccessTokensCacheEntry, bool) {
	r, ok := (*c)[rawToken]
	return r, ok
}

// TestAccess
func (c *AccessTokensCacheEntry) TestAccess(wsvc string) bool {
	_, ok := c.allowedWebservicesCache[wsvc]
	return ok
}
