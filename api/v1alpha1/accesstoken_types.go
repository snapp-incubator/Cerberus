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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// AccessTokenState describes the state of the token and
// shows if it should be included in authorization or not
// +kubebuilder:validation:Enum=Active;Expired;Suspended
type AccessTokenState string

const (
	// Cerberus will allow access to the token
	ActiveState AccessTokenState = "Active"

	// Cerberus won't include the token and user needs to generate new one
	ExpiredState AccessTokenState = "Expired"

	// Cerberus won't include the token but it may become Active again
	SuspendedState AccessTokenState = "Suspended"
)

// AccessTokenSpec defines the desired state of AccessToken
type AccessTokenSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// State shows the state of the token (whether you use token or it's just a draft)
	// Valid values are:
	// - "Active" (default): uses token in authorization procedure
	// - "Expired": won't include token in authorization procedure
	// - "Suspended": shows that the token is currently not usable, but it may become Active later
	// +optional
	State AccessTokenState `json:"state,omitempty"`

	// IP Allow List is a list of IP and IP CIDRs that will be tested against X-Forwarded-For
	// +optional
	IpAllowList []string `json:"ipAllowList,omitempty"`

	// Domain Allow list is a list of Domain glob patterns that will be tested against Referer header
	// +optional
	DomainAllowList []string `json:"domainAllowList,omitempty"`

	// Secret Ref points to secret containing the API Key secret
	// if it exists it will use the token value in it and will create a new secret if not exists
	TokenSecretRef *corev1.LocalObjectReference `json:"secretRef,omitempty"`

	// Priority shows the access level of the token
	// +kubebuilder:default=0
	// +kubebuilder:validation:Minimum=0
	// +optional
	Priority int `json:"priority,omitempty"`
}

// TODO use AccessToken.Metadata.Name as TokenSecretRef
// TODO next step: create copy of secret in AccessToken's namespace

// AccessTokenStatus defines the observed state of AccessToken
type AccessTokenStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// AccessToken is the Schema for the accesstokens API
type AccessToken struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AccessTokenSpec   `json:"spec,omitempty"`
	Status AccessTokenStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// AccessTokenList contains a list of AccessToken
type AccessTokenList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AccessToken `json:"items"`
}

func init() {
	SchemeBuilder.Register(&AccessToken{}, &AccessTokenList{})
}
