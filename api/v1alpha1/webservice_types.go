/*
Copyright 2023.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// WebServiceSpec defines the desired state of WebService
type WebServiceSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// +kubebuilder:default=X-Cerberus-Token
	// +kubebuilder:validation:Pattern=^(X-[A-Za-z-]*[A-Za-z]|Authorization)$
	// LookupHeader tells Cerberus which header should be used as the access token for authentication (case-sensitive).
	LookupHeader string `json:"lookupHeader,omitempty"`

	// UpstreamHttpAuth tells Cerberus whether it needs to forward
	// authentication to another (HTTP) service or not
	// +optional
	UpstreamHttpAuth UpstreamHttpAuthService `json:"upstreamHttpAuth"`

	// IgnoreIP tells Cerberus whether it should check ip list of specific webservice or not
	IgnoreIP bool `json:"ignoreIP"`

	// IgnoreDomain tells Cerberus whether it should check domain list of specific webservice or not
	IgnoreDomain bool `json:"ignoreDomain"`
}

// TODO set default value for LookupHeader

type UpstreamHttpAuthService struct {
	// Address of the upstream authentication service
	Address string `json:"address,omitempty"`

	// +kubebuilder:default=Authorization
	// ReadTokenFrom specifies which header contains the upstream Auth token in the request
	ReadTokenFrom string `json:"readTokenFrom"`

	// +kubebuilder:default=Authorization
	// WriteTokenTo specifies which header should carry token to upstream service
	WriteTokenTo string `json:"writeTokenTo"`

	// CareHeaders specifies which headers from the upstream should be added to the downstream response.
	// +optional
	CareHeaders []string `json:"careHeaders,omitempty"`

	// +kubebuilder:default=200
	// Timeout specifies the milliseconds duration to wait before timing out the request to the upstream authentication service.
	Timeout int `json:"timeout"`
}

// WebServiceStatus defines the observed state of WebService
type WebServiceStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// WebService is the Schema for the webservices API
type WebService struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   WebServiceSpec   `json:"spec,omitempty"`
	Status WebServiceStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// WebServiceList contains a list of WebService
type WebServiceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []WebService `json:"items"`
}

func init() {
	SchemeBuilder.Register(&WebService{}, &WebServiceList{})
}
