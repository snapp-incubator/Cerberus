//go:build !ignore_autogenerated
// +build !ignore_autogenerated

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

// Code generated by controller-gen. DO NOT EDIT.

package v1alpha1

import (
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AccessToken) DeepCopyInto(out *AccessToken) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	out.Status = in.Status
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AccessToken.
func (in *AccessToken) DeepCopy() *AccessToken {
	if in == nil {
		return nil
	}
	out := new(AccessToken)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *AccessToken) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AccessTokenList) DeepCopyInto(out *AccessTokenList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]AccessToken, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AccessTokenList.
func (in *AccessTokenList) DeepCopy() *AccessTokenList {
	if in == nil {
		return nil
	}
	out := new(AccessTokenList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *AccessTokenList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AccessTokenSpec) DeepCopyInto(out *AccessTokenSpec) {
	*out = *in
	if in.AllowedIPs != nil {
		in, out := &in.AllowedIPs, &out.AllowedIPs
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.AllowedDomains != nil {
		in, out := &in.AllowedDomains, &out.AllowedDomains
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.AllowedWebservices != nil {
		in, out := &in.AllowedWebservices, &out.AllowedWebservices
		*out = make([]*WebserviceReference, len(*in))
		for i := range *in {
			if (*in)[i] != nil {
				in, out := &(*in)[i], &(*out)[i]
				*out = new(WebserviceReference)
				**out = **in
			}
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AccessTokenSpec.
func (in *AccessTokenSpec) DeepCopy() *AccessTokenSpec {
	if in == nil {
		return nil
	}
	out := new(AccessTokenSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AccessTokenStatus) DeepCopyInto(out *AccessTokenStatus) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AccessTokenStatus.
func (in *AccessTokenStatus) DeepCopy() *AccessTokenStatus {
	if in == nil {
		return nil
	}
	out := new(AccessTokenStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *LocalWebserviceReference) DeepCopyInto(out *LocalWebserviceReference) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new LocalWebserviceReference.
func (in *LocalWebserviceReference) DeepCopy() *LocalWebserviceReference {
	if in == nil {
		return nil
	}
	out := new(LocalWebserviceReference)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *UpstreamHttpAuthService) DeepCopyInto(out *UpstreamHttpAuthService) {
	*out = *in
	if in.CareHeaders != nil {
		in, out := &in.CareHeaders, &out.CareHeaders
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new UpstreamHttpAuthService.
func (in *UpstreamHttpAuthService) DeepCopy() *UpstreamHttpAuthService {
	if in == nil {
		return nil
	}
	out := new(UpstreamHttpAuthService)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *WebService) DeepCopyInto(out *WebService) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	out.Status = in.Status
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new WebService.
func (in *WebService) DeepCopy() *WebService {
	if in == nil {
		return nil
	}
	out := new(WebService)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *WebService) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *WebServiceList) DeepCopyInto(out *WebServiceList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]WebService, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new WebServiceList.
func (in *WebServiceList) DeepCopy() *WebServiceList {
	if in == nil {
		return nil
	}
	out := new(WebServiceList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *WebServiceList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *WebServiceSpec) DeepCopyInto(out *WebServiceSpec) {
	*out = *in
	in.UpstreamHttpAuth.DeepCopyInto(&out.UpstreamHttpAuth)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new WebServiceSpec.
func (in *WebServiceSpec) DeepCopy() *WebServiceSpec {
	if in == nil {
		return nil
	}
	out := new(WebServiceSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *WebServiceStatus) DeepCopyInto(out *WebServiceStatus) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new WebServiceStatus.
func (in *WebServiceStatus) DeepCopy() *WebServiceStatus {
	if in == nil {
		return nil
	}
	out := new(WebServiceStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *WebserviceAccessBinding) DeepCopyInto(out *WebserviceAccessBinding) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	out.Status = in.Status
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new WebserviceAccessBinding.
func (in *WebserviceAccessBinding) DeepCopy() *WebserviceAccessBinding {
	if in == nil {
		return nil
	}
	out := new(WebserviceAccessBinding)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *WebserviceAccessBinding) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *WebserviceAccessBindingList) DeepCopyInto(out *WebserviceAccessBindingList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]WebserviceAccessBinding, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new WebserviceAccessBindingList.
func (in *WebserviceAccessBindingList) DeepCopy() *WebserviceAccessBindingList {
	if in == nil {
		return nil
	}
	out := new(WebserviceAccessBindingList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *WebserviceAccessBindingList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *WebserviceAccessBindingSpec) DeepCopyInto(out *WebserviceAccessBindingSpec) {
	*out = *in
	if in.Subjects != nil {
		in, out := &in.Subjects, &out.Subjects
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.Webservices != nil {
		in, out := &in.Webservices, &out.Webservices
		*out = make([]LocalWebserviceReference, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new WebserviceAccessBindingSpec.
func (in *WebserviceAccessBindingSpec) DeepCopy() *WebserviceAccessBindingSpec {
	if in == nil {
		return nil
	}
	out := new(WebserviceAccessBindingSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *WebserviceAccessBindingStatus) DeepCopyInto(out *WebserviceAccessBindingStatus) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new WebserviceAccessBindingStatus.
func (in *WebserviceAccessBindingStatus) DeepCopy() *WebserviceAccessBindingStatus {
	if in == nil {
		return nil
	}
	out := new(WebserviceAccessBindingStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *WebserviceReference) DeepCopyInto(out *WebserviceReference) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new WebserviceReference.
func (in *WebserviceReference) DeepCopy() *WebserviceReference {
	if in == nil {
		return nil
	}
	out := new(WebserviceReference)
	in.DeepCopyInto(out)
	return out
}
