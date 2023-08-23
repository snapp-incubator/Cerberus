package auth

import (
	"context"
	"net/http"
	"sync"

	"github.com/go-logr/logr"
	cerberusv1alpha1 "github.com/snapp-incubator/Cerberus/api/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1 "k8s.io/api/core/v1"
)

type Authenticator struct {
	logger logr.Logger

	accessCache   *AccessCache
	servicesCache *ServicesCache
	cacheLock     sync.RWMutex

	updateLock sync.Mutex
}

type AccessCache map[string]AccessCacheEntry
type ServicesCache map[string]struct{}

type AccessCacheEntry struct {
	cerberusv1alpha1.AccessToken
	// limiter Limiter
	allowedServices map[string]struct{}
}

type CerberusReason string

const (
	CerberusReasonOK                 CerberusReason = "ok"
	CerberusReasonUnauthorized       CerberusReason = "unauthorized"
	CerberusReasonTokenEmpty         CerberusReason = "token-empty"
	CerberusReasonLookupEmpty        CerberusReason = "lookup-empty"
	CerberusReasonTokenNotFound      CerberusReason = "token-notfound"
	CerberusReasonWebserviceNotFound CerberusReason = "webservice-notfound"
)

//+kubebuilder:rbac:groups=cerberus.snappcloud.io,resources=accesstokens,verbs=get;list;watch;
//+kubebuilder:rbac:groups=cerberus.snappcloud.io,resources=accesstokens/status,verbs=get;
//+kubebuilder:rbac:groups=cerberus.snappcloud.io,resources=webservices,verbs=get;list;watch;
//+kubebuilder:rbac:groups=cerberus.snappcloud.io,resources=webservices/status,verbs=get;
//+kubebuilder:rbac:groups=cerberus.snappcloud.io,resources=webserviceaccountbindings,verbs=get;list;watch;
//+kubebuilder:rbac:groups=cerberus.snappcloud.io,resources=webserviceaccountbindings/status,verbs=get;
//+kubebuilder:rbac:groups=v1,resources=secrets,verbs=get;list;watch;create;update;patch;delete

func (a *Authenticator) UpdateCache(c client.Client, ctx context.Context) error {
	a.updateLock.Lock()
	defer a.updateLock.Unlock()

	var err error
	tokens := &cerberusv1alpha1.AccessTokenList{}
	secrets := &v1.SecretList{}
	bindings := &cerberusv1alpha1.WebserviceAccessBindingList{}
	webservices := &cerberusv1alpha1.WebServiceList{}

	err = c.List(ctx, tokens)
	if err != nil {
		return err
	}

	err = c.List(ctx, bindings)
	if err != nil {
		return err
	}

	err = c.List(ctx, webservices)
	if err != nil {
		return err
	}

	// TODO find cleaner way to select
	err = c.List(ctx, secrets,
		client.MatchingLabels{"cerberus.snappcloud.io/secret": "true"},
	)
	if err != nil {
		return err
	}

	// convert secret list to map for faster searchs
	secretValues := make(map[string]string)
	for _, secret := range secrets.Items {
		if t, ok := secret.Data["token"]; ok {
			secretValues[secret.Name] = string(t)
		}
	}

	accessTokenRawValue := func(t *cerberusv1alpha1.AccessToken) (string, bool) {
		if t, ok := secretValues[t.Spec.TokenSecretRef.Name]; ok {
			return t, ok
		}
		return "", false
	}

	newAccessCache := make(AccessCache)
	rawToken := make(map[string]string)
	for _, token := range tokens.Items {
		if t, ok := accessTokenRawValue(&token); ok {
			rawToken[token.Name] = t
			newAccessCache[t] = AccessCacheEntry{
				AccessToken:     token,
				allowedServices: make(map[string]struct{}),
			}
		}
	}

	for _, binding := range bindings.Items {
		for _, subject := range binding.Spec.Subjects {
			for _, webservice := range binding.Spec.Webservices {
				if t, ok := rawToken[subject]; ok {
					newAccessCache[t].allowedServices[webservice] = struct{}{}
				}
			}
		}
	}

	newServicesCache := make(ServicesCache)
	for _, webservice := range webservices.Items {
		newServicesCache[webservice.Name] = struct{}{}
	}

	a.cacheLock.Lock()
	defer a.cacheLock.Unlock()
	a.accessCache = &newAccessCache
	a.servicesCache = &newServicesCache
	return nil
}

// TODO reconcile on secret change (list of secrets can be obtained during cahceUpdates)
// func (a *Authenticator) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {

// }

func (a *Authenticator) TestAccess(wsvc string, token string) (bool, CerberusReason) {
	a.cacheLock.RLock()
	defer a.cacheLock.RUnlock()

	if wsvc == "" {
		return false, CerberusReasonLookupEmpty
	}
	if token == "" {
		return false, CerberusReasonTokenEmpty
	}

	if _, ok := (*a.servicesCache)[wsvc]; !ok {
		return false, CerberusReasonWebserviceNotFound
	}
	if _, ok := (*a.accessCache)[token]; !ok {
		return false, CerberusReasonTokenNotFound
	}

	if _, ok := (*a.accessCache)[token].allowedServices[wsvc]; !ok {
		return false, CerberusReasonUnauthorized
	}
	return true, CerberusReasonOK
}

func (a *Authenticator) Check(ctx context.Context, request *Request) (*Response, error) {
	wsvc := request.Request.Header.Get("X-Cerberus-Webservice")
	token := request.Request.Header.Get("X-Cerberus-Token")

	ok, reason := a.TestAccess(wsvc, token)
	var httpStatusCode int
	if ok {
		httpStatusCode = http.StatusOK
	} else {
		httpStatusCode = http.StatusUnauthorized
	}

	return &Response{
		Allow: ok,
		Response: http.Response{
			StatusCode: httpStatusCode,
			Header: http.Header{
				"Auth-Handler":    {"cerberus"},
				"Cerberus-Reason": {string(reason)},
			},
		},
	}, nil
}

func NewAuthenticator(logger logr.Logger) (*Authenticator, error) {
	a := Authenticator{
		logger: logger,
	}
	return &a, nil
}

// func (a *Authenticator) RegisterWithManager(mgr ctrl.Manager) error {
// 	return ctrl.NewControllerManagedBy(mgr).
// 		For(&v1.Secret{}).
// 		Complete(a)
// }
