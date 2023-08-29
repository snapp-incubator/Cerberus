<!-- Code generated by gomarkdoc. DO NOT EDIT -->

# controllers

```go
import "github.com/snapp-incubator/Cerberus/controllers"
```

## Index

- [type AccessTokenReconciler](<#AccessTokenReconciler>)
  - [func \(r \*AccessTokenReconciler\) Reconcile\(ctx context.Context, req ctrl.Request\) \(ctrl.Result, error\)](<#AccessTokenReconciler.Reconcile>)
  - [func \(r \*AccessTokenReconciler\) SetupWithManager\(mgr ctrl.Manager\) error](<#AccessTokenReconciler.SetupWithManager>)
- [type ProcessCache](<#ProcessCache>)
- [type WebServiceReconciler](<#WebServiceReconciler>)
  - [func \(r \*WebServiceReconciler\) Reconcile\(ctx context.Context, req ctrl.Request\) \(ctrl.Result, error\)](<#WebServiceReconciler.Reconcile>)
  - [func \(r \*WebServiceReconciler\) SetupWithManager\(mgr ctrl.Manager\) error](<#WebServiceReconciler.SetupWithManager>)
- [type WebserviceAccessBindingReconciler](<#WebserviceAccessBindingReconciler>)
  - [func \(r \*WebserviceAccessBindingReconciler\) Reconcile\(ctx context.Context, req ctrl.Request\) \(ctrl.Result, error\)](<#WebserviceAccessBindingReconciler.Reconcile>)
  - [func \(r \*WebserviceAccessBindingReconciler\) SetupWithManager\(mgr ctrl.Manager\) error](<#WebserviceAccessBindingReconciler.SetupWithManager>)


<a name="AccessTokenReconciler"></a>
## type [AccessTokenReconciler](<https://github.com/snapp-incubator/Cerberus/blob/main/controllers/accesstoken_controller.go#L31-L35>)

AccessTokenReconciler reconciles a AccessToken object

```go
type AccessTokenReconciler struct {
    client.Client
    Scheme *runtime.Scheme
    Cache  ProcessCache
}
```

<a name="AccessTokenReconciler.Reconcile"></a>
### func \(\*AccessTokenReconciler\) [Reconcile](<https://github.com/snapp-incubator/Cerberus/blob/main/controllers/accesstoken_controller.go#L50>)

```go
func (r *AccessTokenReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error)
```

Reconcile is part of the main kubernetes reconciliation loop which aims to move the current state of the cluster closer to the desired state. TODO\(user\): Modify the Reconcile function to compare the state specified by the AccessToken object against the actual cluster state, and then perform operations to make the cluster state reflect the state specified by the user.

For more details, check Reconcile and its Result here: \- https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.14.1/pkg/reconcile

<a name="AccessTokenReconciler.SetupWithManager"></a>
### func \(\*AccessTokenReconciler\) [SetupWithManager](<https://github.com/snapp-incubator/Cerberus/blob/main/controllers/accesstoken_controller.go#L59>)

```go
func (r *AccessTokenReconciler) SetupWithManager(mgr ctrl.Manager) error
```

SetupWithManager sets up the controller with the Manager.

<a name="ProcessCache"></a>
## type [ProcessCache](<https://github.com/snapp-incubator/Cerberus/blob/main/controllers/cache.go#L9-L11>)



```go
type ProcessCache interface {
    UpdateCache(client.Client, context.Context) error
}
```

<a name="WebServiceReconciler"></a>
## type [WebServiceReconciler](<https://github.com/snapp-incubator/Cerberus/blob/main/controllers/webservice_controller.go#L31-L35>)

WebServiceReconciler reconciles a WebService object

```go
type WebServiceReconciler struct {
    client.Client
    Scheme *runtime.Scheme
    Cache  ProcessCache
}
```

<a name="WebServiceReconciler.Reconcile"></a>
### func \(\*WebServiceReconciler\) [Reconcile](<https://github.com/snapp-incubator/Cerberus/blob/main/controllers/webservice_controller.go#L50>)

```go
func (r *WebServiceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error)
```

Reconcile is part of the main kubernetes reconciliation loop which aims to move the current state of the cluster closer to the desired state. TODO\(user\): Modify the Reconcile function to compare the state specified by the WebService object against the actual cluster state, and then perform operations to make the cluster state reflect the state specified by the user.

For more details, check Reconcile and its Result here: \- https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.14.1/pkg/reconcile

<a name="WebServiceReconciler.SetupWithManager"></a>
### func \(\*WebServiceReconciler\) [SetupWithManager](<https://github.com/snapp-incubator/Cerberus/blob/main/controllers/webservice_controller.go#L59>)

```go
func (r *WebServiceReconciler) SetupWithManager(mgr ctrl.Manager) error
```

SetupWithManager sets up the controller with the Manager.

<a name="WebserviceAccessBindingReconciler"></a>
## type [WebserviceAccessBindingReconciler](<https://github.com/snapp-incubator/Cerberus/blob/main/controllers/webserviceaccessbinding_controller.go#L31-L35>)

WebserviceAccessBindingReconciler reconciles a WebserviceAccessBinding object

```go
type WebserviceAccessBindingReconciler struct {
    client.Client
    Scheme *runtime.Scheme
    Cache  ProcessCache
}
```

<a name="WebserviceAccessBindingReconciler.Reconcile"></a>
### func \(\*WebserviceAccessBindingReconciler\) [Reconcile](<https://github.com/snapp-incubator/Cerberus/blob/main/controllers/webserviceaccessbinding_controller.go#L50>)

```go
func (r *WebserviceAccessBindingReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error)
```

Reconcile is part of the main kubernetes reconciliation loop which aims to move the current state of the cluster closer to the desired state. TODO\(user\): Modify the Reconcile function to compare the state specified by the WebserviceAccessBinding object against the actual cluster state, and then perform operations to make the cluster state reflect the state specified by the user.

For more details, check Reconcile and its Result here: \- https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.14.1/pkg/reconcile

<a name="WebserviceAccessBindingReconciler.SetupWithManager"></a>
### func \(\*WebserviceAccessBindingReconciler\) [SetupWithManager](<https://github.com/snapp-incubator/Cerberus/blob/main/controllers/webserviceaccessbinding_controller.go#L59>)

```go
func (r *WebserviceAccessBindingReconciler) SetupWithManager(mgr ctrl.Manager) error
```

SetupWithManager sets up the controller with the Manager.

Generated by [gomarkdoc](<https://github.com/princjef/gomarkdoc>)