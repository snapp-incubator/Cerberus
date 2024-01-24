package auth

import (
	"context"
	"reflect"
	"time"

	"github.com/snapp-incubator/Cerberus/api/v1alpha1"
	cerberusv1alpha1 "github.com/snapp-incubator/Cerberus/api/v1alpha1"
	v1 "k8s.io/api/core/v1"
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
	cerberusv1alpha1.AccessToken
	rawToken                string
	allowedWebservicesCache AllowedWebservicesCache
}

// AllowedWebserviceCache will hold which Webservices in which Namespaces does the AccessToken
// has access to (e.g AccessCache["ns-123"]["wsvc-123"] is present
// if the corresponding AccessToken has access to <wsvc-123> in namespace <ns-123>)
type AllowedWebservicesCache map[string]map[string]struct{}

// WebservicesCacheEntry will hold all datas included in Webservice manifest
type WebservicesCacheEntry struct {
	cerberusv1alpha1.WebService
	allowedNamespacesCache AllowedNamespacesCache
}

// AllowedNamespacesCache will hold all namespaces that are allowed to call this webservice
type AllowedNamespacesCache map[string]struct{}

//+kubebuilder:rbac:groups=cerberus.snappcloud.io,resources=accesstokens,verbs=get;list;watch;
//+kubebuilder:rbac:groups=cerberus.snappcloud.io,resources=accesstokens/status,verbs=get;
//+kubebuilder:rbac:groups=cerberus.snappcloud.io,resources=webservices,verbs=get;list;watch;
//+kubebuilder:rbac:groups=cerberus.snappcloud.io,resources=webservices/status,verbs=get;
//+kubebuilder:rbac:groups=cerberus.snappcloud.io,resources=webserviceaccountbindings,verbs=get;list;watch;
//+kubebuilder:rbac:groups=cerberus.snappcloud.io,resources=webserviceaccountbindings/status,verbs=get;
//+kubebuilder:rbac:groups="",namespace='cerberus-operator-system',resources=secrets,verbs=get;list;watch;create;update;patch;delete

// UpdateCache will accuire a lock on other UpdateCaches and will start to recreate
// the entire AccessCache and WebserviceCaches (which contains all authentication information)
func (a *Authenticator) UpdateCache(c client.Client, ctx context.Context, readOnly bool) (err error) {
	cacheUpdateCount.Inc()
	cacheUpdateStartTime := time.Now()
	defer func() {
		cacheUpdateLatency.Observe(time.Since(cacheUpdateStartTime).Seconds())
	}()

	a.updateLock.Lock()
	defer a.updateLock.Unlock()

	tokens, err := retrieveObjects[*cerberusv1alpha1.AccessTokenList](c, ctx)
	if err != nil {
		return
	}

	secrets, err := retrieveObjects[*v1.SecretList](c, ctx)
	if err != nil {
		return
	}

	bindings, err := retrieveObjects[*cerberusv1alpha1.WebserviceAccessBindingList](c, ctx)
	if err != nil {
		return
	}

	webservices, err := retrieveObjects[*cerberusv1alpha1.WebServiceList](c, ctx)
	if err != nil {
		return
	}

	buildNewWebservicesCache(webservices, bindings)

	// TODO: remove this line
	a.logger.Info("new access cache", "accessCache", newAccessCache, "servicesCache", newServicesCache)

	cacheWriteLockRequestStartTime := time.Now()
	a.cacheLock.Lock()
	cacheWriteLockWaitingTime.Observe(time.Since(cacheWriteLockRequestStartTime).Seconds())
	defer a.cacheLock.Unlock()

	cacheWriteStartTime := time.Now()
	a.accessCache = &newAccessCache
	a.servicesCache = &newServicesCache
	cacheWriteTime.Observe(time.Since(cacheWriteStartTime).Seconds())
	return nil
}

// retrieveObjects is a generic function which will list all the Objects matching given type
// from API Server using given k8s client and ctx and returns a pointer to a list of them
func retrieveObjects[K client.ObjectList](
	c client.Client,
	ctx context.Context,
	listOpts ...*client.ListOptions,
) (
	K, error,
) {
	t := time.Now()

	var result K
	elemType := reflect.TypeOf(result).Elem()
	newInstance := reflect.New(elemType).Elem()
	reflect.ValueOf(result).Elem().Set(newInstance)
	metricsLabel := reflect.TypeOf(newInstance).String()

	err := c.List(ctx, result)
	fetchObjectListLatency.With(AddKindLabel(nil, metricsLabel)).Observe(time.Since(t).Seconds())
	return result, err
}

func buildNewAccessTokensCache(
	tokens *v1alpha1.AccessTokenList,
	secrets *v1.SecretList,
	bindings *v1alpha1.WebserviceAccessBindingList,
) *AccessTokensCache {
	secretValues := getSecretRawTokenMap(secrets)

	newAccessTokensCache := make(AccessTokensCache)

	rawToken := make(map[string]string)
	for _, token := range tokens.Items {
		if t, ok := secretValues[token.Namespace+"."+token.Name]; ok {
			rawToken[token.Name] = t
			newAccessTokensCache[t] = AccessTokensCacheEntry{
				AccessToken:             token,
				allowedWebservicesCache: make(AllowedWebservicesCache),
				rawToken:                t,
			}
		}
	}
	accessCacheEntries.Set(float64(len(newAccessTokensCache)))
	newAccessTokensCache.buildAllowedWebservicesCache()
	return &newAccessTokensCache
}

func buildNewWebservicesCache(webservices *v1alpha1.WebServiceList, bindings *v1alpha1.WebserviceAccessBindingList) *WebservicesCache {
	newWebservicesCache := make(WebservicesCache)
	for _, webservice := range webservices.Items {
		newWebservicesCache[webservice.Name] = WebservicesCacheEntry{
			WebService:             webservice,
			allowedNamespacesCache: make(AllowedNamespacesCache),
		}
	}
	webserviceCacheEntries.Set(float64(len(newWebservicesCache)))

	newWebservicesCache.buildAllowedNamespacesCache(bindings)
	return &newWebservicesCache
}

func (c *WebservicesCache) buildAllowedNamespacesCache(bindings *v1alpha1.WebserviceAccessBindingList) {
	// for _, binding := range bindings.I
}

// getSecretRawTokenMap converts a secret list to a map from secret name to it's
// token field value for faster access to token values by secret name
func getSecretRawTokenMap(secrets *v1.SecretList) map[string]string {
	result := make(map[string]string)
	for _, secret := range secrets.Items {
		if t, ok := secret.Data["token"]; ok {
			result[secret.Name] = string(t)
		}
	}
	return result
}

func (c *AccessTokensCache) buildAllowedWebservicesCache(bindings *v1alpha1.WebserviceAccessBindingList) {
	for _, binding := range bindings.Items {
		for _, subject := range binding.Spec.Subjects {
			for _, webservice := range binding.Spec.Webservices {
				if t, ok := rawToken[subject]; ok {
					newAccessTokensCache[t].allowedWebservicesCache[webservice] = struct{}{}
				}
			}
		}
	}
}
