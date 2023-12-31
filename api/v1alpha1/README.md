<!-- Code generated by gomarkdoc. DO NOT EDIT -->

# v1alpha1

```go
import "github.com/snapp-incubator/Cerberus/api/v1alpha1"
```

Package v1alpha1 contains API Schema definitions for the cerberus v1alpha1 API group \+kubebuilder:object:generate=true \+groupName=cerberus.snappcloud.io

## Index

- [Variables](<#variables>)
- [type AccessToken](<#AccessToken>)
  - [func \(in \*AccessToken\) DeepCopy\(\) \*AccessToken](<#AccessToken.DeepCopy>)
  - [func \(in \*AccessToken\) DeepCopyInto\(out \*AccessToken\)](<#AccessToken.DeepCopyInto>)
  - [func \(in \*AccessToken\) DeepCopyObject\(\) runtime.Object](<#AccessToken.DeepCopyObject>)
- [type AccessTokenList](<#AccessTokenList>)
  - [func \(in \*AccessTokenList\) DeepCopy\(\) \*AccessTokenList](<#AccessTokenList.DeepCopy>)
  - [func \(in \*AccessTokenList\) DeepCopyInto\(out \*AccessTokenList\)](<#AccessTokenList.DeepCopyInto>)
  - [func \(in \*AccessTokenList\) DeepCopyObject\(\) runtime.Object](<#AccessTokenList.DeepCopyObject>)
- [type AccessTokenSpec](<#AccessTokenSpec>)
  - [func \(in \*AccessTokenSpec\) DeepCopy\(\) \*AccessTokenSpec](<#AccessTokenSpec.DeepCopy>)
  - [func \(in \*AccessTokenSpec\) DeepCopyInto\(out \*AccessTokenSpec\)](<#AccessTokenSpec.DeepCopyInto>)
- [type AccessTokenState](<#AccessTokenState>)
- [type AccessTokenStatus](<#AccessTokenStatus>)
  - [func \(in \*AccessTokenStatus\) DeepCopy\(\) \*AccessTokenStatus](<#AccessTokenStatus.DeepCopy>)
  - [func \(in \*AccessTokenStatus\) DeepCopyInto\(out \*AccessTokenStatus\)](<#AccessTokenStatus.DeepCopyInto>)
- [type UpstreamHttpAuthService](<#UpstreamHttpAuthService>)
- [type WebService](<#WebService>)
  - [func \(in \*WebService\) DeepCopy\(\) \*WebService](<#WebService.DeepCopy>)
  - [func \(in \*WebService\) DeepCopyInto\(out \*WebService\)](<#WebService.DeepCopyInto>)
  - [func \(in \*WebService\) DeepCopyObject\(\) runtime.Object](<#WebService.DeepCopyObject>)
- [type WebServiceList](<#WebServiceList>)
  - [func \(in \*WebServiceList\) DeepCopy\(\) \*WebServiceList](<#WebServiceList.DeepCopy>)
  - [func \(in \*WebServiceList\) DeepCopyInto\(out \*WebServiceList\)](<#WebServiceList.DeepCopyInto>)
  - [func \(in \*WebServiceList\) DeepCopyObject\(\) runtime.Object](<#WebServiceList.DeepCopyObject>)
- [type WebServiceSpec](<#WebServiceSpec>)
  - [func \(in \*WebServiceSpec\) DeepCopy\(\) \*WebServiceSpec](<#WebServiceSpec.DeepCopy>)
  - [func \(in \*WebServiceSpec\) DeepCopyInto\(out \*WebServiceSpec\)](<#WebServiceSpec.DeepCopyInto>)
- [type WebServiceStatus](<#WebServiceStatus>)
  - [func \(in \*WebServiceStatus\) DeepCopy\(\) \*WebServiceStatus](<#WebServiceStatus.DeepCopy>)
  - [func \(in \*WebServiceStatus\) DeepCopyInto\(out \*WebServiceStatus\)](<#WebServiceStatus.DeepCopyInto>)
- [type WebserviceAccessBinding](<#WebserviceAccessBinding>)
  - [func \(in \*WebserviceAccessBinding\) DeepCopy\(\) \*WebserviceAccessBinding](<#WebserviceAccessBinding.DeepCopy>)
  - [func \(in \*WebserviceAccessBinding\) DeepCopyInto\(out \*WebserviceAccessBinding\)](<#WebserviceAccessBinding.DeepCopyInto>)
  - [func \(in \*WebserviceAccessBinding\) DeepCopyObject\(\) runtime.Object](<#WebserviceAccessBinding.DeepCopyObject>)
- [type WebserviceAccessBindingList](<#WebserviceAccessBindingList>)
  - [func \(in \*WebserviceAccessBindingList\) DeepCopy\(\) \*WebserviceAccessBindingList](<#WebserviceAccessBindingList.DeepCopy>)
  - [func \(in \*WebserviceAccessBindingList\) DeepCopyInto\(out \*WebserviceAccessBindingList\)](<#WebserviceAccessBindingList.DeepCopyInto>)
  - [func \(in \*WebserviceAccessBindingList\) DeepCopyObject\(\) runtime.Object](<#WebserviceAccessBindingList.DeepCopyObject>)
- [type WebserviceAccessBindingSpec](<#WebserviceAccessBindingSpec>)
  - [func \(in \*WebserviceAccessBindingSpec\) DeepCopy\(\) \*WebserviceAccessBindingSpec](<#WebserviceAccessBindingSpec.DeepCopy>)
  - [func \(in \*WebserviceAccessBindingSpec\) DeepCopyInto\(out \*WebserviceAccessBindingSpec\)](<#WebserviceAccessBindingSpec.DeepCopyInto>)
- [type WebserviceAccessBindingStatus](<#WebserviceAccessBindingStatus>)
  - [func \(in \*WebserviceAccessBindingStatus\) DeepCopy\(\) \*WebserviceAccessBindingStatus](<#WebserviceAccessBindingStatus.DeepCopy>)
  - [func \(in \*WebserviceAccessBindingStatus\) DeepCopyInto\(out \*WebserviceAccessBindingStatus\)](<#WebserviceAccessBindingStatus.DeepCopyInto>)


## Variables

<a name="GroupVersion"></a>

```go
var (
    // GroupVersion is group version used to register these objects
    GroupVersion = schema.GroupVersion{Group: "cerberus.snappcloud.io", Version: "v1alpha1"}

    // SchemeBuilder is used to add go types to the GroupVersionKind scheme
    SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}

    // AddToScheme adds the types in this group-version to the given scheme.
    AddToScheme = SchemeBuilder.AddToScheme
)
```

<a name="AccessToken"></a>
## type [AccessToken](<https://github.com/snapp-incubator/Cerberus/blob/main/api/v1alpha1/accesstoken_types.go#L82-L88>)

AccessToken is the Schema for the accesstokens API

```go
type AccessToken struct {
    metav1.TypeMeta   `json:",inline"`
    metav1.ObjectMeta `json:"metadata,omitempty"`

    Spec   AccessTokenSpec   `json:"spec,omitempty"`
    Status AccessTokenStatus `json:"status,omitempty"`
}
```

<a name="AccessToken.DeepCopy"></a>
### func \(\*AccessToken\) [DeepCopy](<https://github.com/snapp-incubator/Cerberus/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L39>)

```go
func (in *AccessToken) DeepCopy() *AccessToken
```

DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AccessToken.

<a name="AccessToken.DeepCopyInto"></a>
### func \(\*AccessToken\) [DeepCopyInto](<https://github.com/snapp-incubator/Cerberus/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L30>)

```go
func (in *AccessToken) DeepCopyInto(out *AccessToken)
```

DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non\-nil.

<a name="AccessToken.DeepCopyObject"></a>
### func \(\*AccessToken\) [DeepCopyObject](<https://github.com/snapp-incubator/Cerberus/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L49>)

```go
func (in *AccessToken) DeepCopyObject() runtime.Object
```

DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.

<a name="AccessTokenList"></a>
## type [AccessTokenList](<https://github.com/snapp-incubator/Cerberus/blob/main/api/v1alpha1/accesstoken_types.go#L93-L97>)

AccessTokenList contains a list of AccessToken

```go
type AccessTokenList struct {
    metav1.TypeMeta `json:",inline"`
    metav1.ListMeta `json:"metadata,omitempty"`
    Items           []AccessToken `json:"items"`
}
```

<a name="AccessTokenList.DeepCopy"></a>
### func \(\*AccessTokenList\) [DeepCopy](<https://github.com/snapp-incubator/Cerberus/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L71>)

```go
func (in *AccessTokenList) DeepCopy() *AccessTokenList
```

DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AccessTokenList.

<a name="AccessTokenList.DeepCopyInto"></a>
### func \(\*AccessTokenList\) [DeepCopyInto](<https://github.com/snapp-incubator/Cerberus/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L57>)

```go
func (in *AccessTokenList) DeepCopyInto(out *AccessTokenList)
```

DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non\-nil.

<a name="AccessTokenList.DeepCopyObject"></a>
### func \(\*AccessTokenList\) [DeepCopyObject](<https://github.com/snapp-incubator/Cerberus/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L81>)

```go
func (in *AccessTokenList) DeepCopyObject() runtime.Object
```

DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.

<a name="AccessTokenSpec"></a>
## type [AccessTokenSpec](<https://github.com/snapp-incubator/Cerberus/blob/main/api/v1alpha1/accesstoken_types.go#L44-L67>)

AccessTokenSpec defines the desired state of AccessToken

```go
type AccessTokenSpec struct {

    // State shows the state of the token (whether use token or it's just a draft)
    // Valid values are:
    // - "Active" (default): uses token in authorization procedure
    // - "Expired": won't include token in authorization procedure
    // - "Suspended": shows that the token is currently not usable but it may become Active later
    // +optional
    State AccessTokenState `json:"active,omitempty"`

    // IP Allow List is a list of IP and IP CIDRs that will be tested against X-Forwarded-For
    // +optional
    IpAllowList []string `json:"ipAllowList,omitempty"`

    // Domain Allow list is a list of Domain glob patterns that will be tested against Referer header
    // +optional
    DomainAllowList []string `json:"domainAllowList,omitempty"`

    // Secret Ref points to secret containing the API Key secret
    // if it exists it will use the token value in it and will create a new secret if not exists
    TokenSecretRef *corev1.LocalObjectReference `json:"secretRef,omitempty"`
}
```

<a name="AccessTokenSpec.DeepCopy"></a>
### func \(\*AccessTokenSpec\) [DeepCopy](<https://github.com/snapp-incubator/Cerberus/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L109>)

```go
func (in *AccessTokenSpec) DeepCopy() *AccessTokenSpec
```

DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AccessTokenSpec.

<a name="AccessTokenSpec.DeepCopyInto"></a>
### func \(\*AccessTokenSpec\) [DeepCopyInto](<https://github.com/snapp-incubator/Cerberus/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L89>)

```go
func (in *AccessTokenSpec) DeepCopyInto(out *AccessTokenSpec)
```

DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non\-nil.

<a name="AccessTokenState"></a>
## type [AccessTokenState](<https://github.com/snapp-incubator/Cerberus/blob/main/api/v1alpha1/accesstoken_types.go#L30>)

AccessTokenState describes the state of the token and shows if it should be included in authorization or not \+kubebuilder:validation:Enum=Active;Expired;Suspended

```go
type AccessTokenState string
```

<a name="ActiveState"></a>

```go
const (
    // Cerberus will allow access to the token
    ActiveState AccessTokenState = "Active"

    // Cerberus won't include the token and user needs to generate new one
    ExpiredState AccessTokenState = "Expired"

    // Cerberus won't include the token but it may become Active again
    SuspendedState AccessTokenState = "Suspended"
)
```

<a name="AccessTokenStatus"></a>
## type [AccessTokenStatus](<https://github.com/snapp-incubator/Cerberus/blob/main/api/v1alpha1/accesstoken_types.go#L73-L76>)

AccessTokenStatus defines the observed state of AccessToken

```go
type AccessTokenStatus struct {
}
```

<a name="AccessTokenStatus.DeepCopy"></a>
### func \(\*AccessTokenStatus\) [DeepCopy](<https://github.com/snapp-incubator/Cerberus/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L124>)

```go
func (in *AccessTokenStatus) DeepCopy() *AccessTokenStatus
```

DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AccessTokenStatus.

<a name="AccessTokenStatus.DeepCopyInto"></a>
### func \(\*AccessTokenStatus\) [DeepCopyInto](<https://github.com/snapp-incubator/Cerberus/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L119>)

```go
func (in *AccessTokenStatus) DeepCopyInto(out *AccessTokenStatus)
```

DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non\-nil.

<a name="UpstreamHttpAuthService"></a>
## type [UpstreamHttpAuthService](<https://github.com/snapp-incubator/Cerberus/blob/main/api/v1alpha1/webservice_types.go#L42-L53>)



```go
type UpstreamHttpAuthService struct {
    // Address of the upstream authentication service
    Address string `json:"address,omitempty"`

    // +kubebuilder:default=Authorization
    // ReadTokenFrom specifies which header contains the upstream Auth token in the request
    ReadTokenFrom string `json:"readTokenFrom"`

    // +kubebuilder:default=Authorization
    // WriteTokenTo specifies which header should carry token to upstream service
    WriteTokenTo string `json:"writeTokenTo"`
}
```

<a name="WebService"></a>
## type [WebService](<https://github.com/snapp-incubator/Cerberus/blob/main/api/v1alpha1/webservice_types.go#L65-L71>)

WebService is the Schema for the webservices API

```go
type WebService struct {
    metav1.TypeMeta   `json:",inline"`
    metav1.ObjectMeta `json:"metadata,omitempty"`

    Spec   WebServiceSpec   `json:"spec,omitempty"`
    Status WebServiceStatus `json:"status,omitempty"`
}
```

<a name="WebService.DeepCopy"></a>
### func \(\*WebService\) [DeepCopy](<https://github.com/snapp-incubator/Cerberus/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L143>)

```go
func (in *WebService) DeepCopy() *WebService
```

DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new WebService.

<a name="WebService.DeepCopyInto"></a>
### func \(\*WebService\) [DeepCopyInto](<https://github.com/snapp-incubator/Cerberus/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L134>)

```go
func (in *WebService) DeepCopyInto(out *WebService)
```

DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non\-nil.

<a name="WebService.DeepCopyObject"></a>
### func \(\*WebService\) [DeepCopyObject](<https://github.com/snapp-incubator/Cerberus/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L153>)

```go
func (in *WebService) DeepCopyObject() runtime.Object
```

DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.

<a name="WebServiceList"></a>
## type [WebServiceList](<https://github.com/snapp-incubator/Cerberus/blob/main/api/v1alpha1/webservice_types.go#L76-L80>)

WebServiceList contains a list of WebService

```go
type WebServiceList struct {
    metav1.TypeMeta `json:",inline"`
    metav1.ListMeta `json:"metadata,omitempty"`
    Items           []WebService `json:"items"`
}
```

<a name="WebServiceList.DeepCopy"></a>
### func \(\*WebServiceList\) [DeepCopy](<https://github.com/snapp-incubator/Cerberus/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L175>)

```go
func (in *WebServiceList) DeepCopy() *WebServiceList
```

DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new WebServiceList.

<a name="WebServiceList.DeepCopyInto"></a>
### func \(\*WebServiceList\) [DeepCopyInto](<https://github.com/snapp-incubator/Cerberus/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L161>)

```go
func (in *WebServiceList) DeepCopyInto(out *WebServiceList)
```

DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non\-nil.

<a name="WebServiceList.DeepCopyObject"></a>
### func \(\*WebServiceList\) [DeepCopyObject](<https://github.com/snapp-incubator/Cerberus/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L185>)

```go
func (in *WebServiceList) DeepCopyObject() runtime.Object
```

DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.

<a name="WebServiceSpec"></a>
## type [WebServiceSpec](<https://github.com/snapp-incubator/Cerberus/blob/main/api/v1alpha1/webservice_types.go#L27-L38>)

WebServiceSpec defines the desired state of WebService

```go
type WebServiceSpec struct {

    // LookupHeader tells Cerberus which header should be used as Webservice name for the authentication
    LookupHeader string `json:"lookupHeader,omitempty"`

    // UpstreamHttpAuth tells Cerberus whether it needs to forward
    // authentication to another (HTTP) service or not
    // +optional
    UpstreamHttpAuth UpstreamHttpAuthService `json:"upstreamHttpAuth"`
}
```

<a name="WebServiceSpec.DeepCopy"></a>
### func \(\*WebServiceSpec\) [DeepCopy](<https://github.com/snapp-incubator/Cerberus/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L198>)

```go
func (in *WebServiceSpec) DeepCopy() *WebServiceSpec
```

DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new WebServiceSpec.

<a name="WebServiceSpec.DeepCopyInto"></a>
### func \(\*WebServiceSpec\) [DeepCopyInto](<https://github.com/snapp-incubator/Cerberus/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L193>)

```go
func (in *WebServiceSpec) DeepCopyInto(out *WebServiceSpec)
```

DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non\-nil.

<a name="WebServiceStatus"></a>
## type [WebServiceStatus](<https://github.com/snapp-incubator/Cerberus/blob/main/api/v1alpha1/webservice_types.go#L56-L59>)

WebServiceStatus defines the observed state of WebService

```go
type WebServiceStatus struct {
}
```

<a name="WebServiceStatus.DeepCopy"></a>
### func \(\*WebServiceStatus\) [DeepCopy](<https://github.com/snapp-incubator/Cerberus/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L213>)

```go
func (in *WebServiceStatus) DeepCopy() *WebServiceStatus
```

DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new WebServiceStatus.

<a name="WebServiceStatus.DeepCopyInto"></a>
### func \(\*WebServiceStatus\) [DeepCopyInto](<https://github.com/snapp-incubator/Cerberus/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L208>)

```go
func (in *WebServiceStatus) DeepCopyInto(out *WebServiceStatus)
```

DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non\-nil.

<a name="WebserviceAccessBinding"></a>
## type [WebserviceAccessBinding](<https://github.com/snapp-incubator/Cerberus/blob/main/api/v1alpha1/webserviceaccessbinding_types.go#L48-L54>)

WebserviceAccessBinding is the Schema for the webserviceaccessbindings API

```go
type WebserviceAccessBinding struct {
    metav1.TypeMeta   `json:",inline"`
    metav1.ObjectMeta `json:"metadata,omitempty"`

    Spec   WebserviceAccessBindingSpec   `json:"spec,omitempty"`
    Status WebserviceAccessBindingStatus `json:"status,omitempty"`
}
```

<a name="WebserviceAccessBinding.DeepCopy"></a>
### func \(\*WebserviceAccessBinding\) [DeepCopy](<https://github.com/snapp-incubator/Cerberus/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L232>)

```go
func (in *WebserviceAccessBinding) DeepCopy() *WebserviceAccessBinding
```

DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new WebserviceAccessBinding.

<a name="WebserviceAccessBinding.DeepCopyInto"></a>
### func \(\*WebserviceAccessBinding\) [DeepCopyInto](<https://github.com/snapp-incubator/Cerberus/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L223>)

```go
func (in *WebserviceAccessBinding) DeepCopyInto(out *WebserviceAccessBinding)
```

DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non\-nil.

<a name="WebserviceAccessBinding.DeepCopyObject"></a>
### func \(\*WebserviceAccessBinding\) [DeepCopyObject](<https://github.com/snapp-incubator/Cerberus/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L242>)

```go
func (in *WebserviceAccessBinding) DeepCopyObject() runtime.Object
```

DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.

<a name="WebserviceAccessBindingList"></a>
## type [WebserviceAccessBindingList](<https://github.com/snapp-incubator/Cerberus/blob/main/api/v1alpha1/webserviceaccessbinding_types.go#L59-L63>)

WebserviceAccessBindingList contains a list of WebserviceAccessBinding

```go
type WebserviceAccessBindingList struct {
    metav1.TypeMeta `json:",inline"`
    metav1.ListMeta `json:"metadata,omitempty"`
    Items           []WebserviceAccessBinding `json:"items"`
}
```

<a name="WebserviceAccessBindingList.DeepCopy"></a>
### func \(\*WebserviceAccessBindingList\) [DeepCopy](<https://github.com/snapp-incubator/Cerberus/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L264>)

```go
func (in *WebserviceAccessBindingList) DeepCopy() *WebserviceAccessBindingList
```

DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new WebserviceAccessBindingList.

<a name="WebserviceAccessBindingList.DeepCopyInto"></a>
### func \(\*WebserviceAccessBindingList\) [DeepCopyInto](<https://github.com/snapp-incubator/Cerberus/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L250>)

```go
func (in *WebserviceAccessBindingList) DeepCopyInto(out *WebserviceAccessBindingList)
```

DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non\-nil.

<a name="WebserviceAccessBindingList.DeepCopyObject"></a>
### func \(\*WebserviceAccessBindingList\) [DeepCopyObject](<https://github.com/snapp-incubator/Cerberus/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L274>)

```go
func (in *WebserviceAccessBindingList) DeepCopyObject() runtime.Object
```

DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.

<a name="WebserviceAccessBindingSpec"></a>
## type [WebserviceAccessBindingSpec](<https://github.com/snapp-incubator/Cerberus/blob/main/api/v1alpha1/webserviceaccessbinding_types.go#L27-L36>)

WebserviceAccessBindingSpec defines the desired state of WebserviceAccessBinding

```go
type WebserviceAccessBindingSpec struct {

    // Subjects are the name of AccessTokens which the access will be granted to
    Subjects []string `json:"subjects,omitempty"`

    // WebServices are the target service accesses
    Webservices []string `json:"webservices,omitempty"`
}
```

<a name="WebserviceAccessBindingSpec.DeepCopy"></a>
### func \(\*WebserviceAccessBindingSpec\) [DeepCopy](<https://github.com/snapp-incubator/Cerberus/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L287>)

```go
func (in *WebserviceAccessBindingSpec) DeepCopy() *WebserviceAccessBindingSpec
```

DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new WebserviceAccessBindingSpec.

<a name="WebserviceAccessBindingSpec.DeepCopyInto"></a>
### func \(\*WebserviceAccessBindingSpec\) [DeepCopyInto](<https://github.com/snapp-incubator/Cerberus/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L282>)

```go
func (in *WebserviceAccessBindingSpec) DeepCopyInto(out *WebserviceAccessBindingSpec)
```

DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non\-nil.

<a name="WebserviceAccessBindingStatus"></a>
## type [WebserviceAccessBindingStatus](<https://github.com/snapp-incubator/Cerberus/blob/main/api/v1alpha1/webserviceaccessbinding_types.go#L39-L42>)

WebserviceAccessBindingStatus defines the observed state of WebserviceAccessBinding

```go
type WebserviceAccessBindingStatus struct {
}
```

<a name="WebserviceAccessBindingStatus.DeepCopy"></a>
### func \(\*WebserviceAccessBindingStatus\) [DeepCopy](<https://github.com/snapp-incubator/Cerberus/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L302>)

```go
func (in *WebserviceAccessBindingStatus) DeepCopy() *WebserviceAccessBindingStatus
```

DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new WebserviceAccessBindingStatus.

<a name="WebserviceAccessBindingStatus.DeepCopyInto"></a>
### func \(\*WebserviceAccessBindingStatus\) [DeepCopyInto](<https://github.com/snapp-incubator/Cerberus/blob/main/api/v1alpha1/zz_generated.deepcopy.go#L297>)

```go
func (in *WebserviceAccessBindingStatus) DeepCopyInto(out *WebserviceAccessBindingStatus)
```

DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non\-nil.

Generated by [gomarkdoc](<https://github.com/princjef/gomarkdoc>)
