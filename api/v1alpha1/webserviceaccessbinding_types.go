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

// WebserviceAccessBindingSpec defines the desired state of WebserviceAccessBinding
type WebserviceAccessBindingSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// Subjects are the name of AccessTokens which the access will be granted to
	Subjects []string `json:"subjects,omitempty"`

	// WebServices are the target service accesses
	Webservices []string `json:"webservices,omitempty"`
}

// WebserviceAccessBindingStatus defines the observed state of WebserviceAccessBinding
type WebserviceAccessBindingStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// WebserviceAccessBinding is the Schema for the webserviceaccessbindings API
type WebserviceAccessBinding struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   WebserviceAccessBindingSpec   `json:"spec,omitempty"`
	Status WebserviceAccessBindingStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// WebserviceAccessBindingList contains a list of WebserviceAccessBinding
type WebserviceAccessBindingList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []WebserviceAccessBinding `json:"items"`
}

func init() {
	SchemeBuilder.Register(&WebserviceAccessBinding{}, &WebserviceAccessBindingList{})
}
