package auth

import (
	"fmt"
	"net/http"
	"net/url"

	envoy_api_v2_core "github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_service_auth_v2 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	envoy_service_auth_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type"
	envoy_type_v3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
)

// Request captures the information needed to process a CheckRequest.
type Request struct {
	Context map[string]string
	Request http.Request
	ID      string
}

// FromV2 initializes a Request from a v2 CheckRequest.
func (r *Request) FromV2(c *CheckRequestV2) *Request {
	r.Request = http.Request{
		URL: &url.URL{
			Scheme:   c.GetAttributes().GetRequest().GetHttp().GetScheme(),
			Host:     c.GetAttributes().GetRequest().GetHttp().GetHost(),
			Path:     c.GetAttributes().GetRequest().GetHttp().GetPath(),
			RawQuery: c.GetAttributes().GetRequest().GetHttp().GetQuery(),
			Fragment: c.GetAttributes().GetRequest().GetHttp().GetFragment(),
		},
		Header: http.Header{},
		Method: c.GetAttributes().GetRequest().GetHttp().GetMethod(),
		Proto:  c.GetAttributes().GetRequest().GetHttp().GetProtocol(),
		RemoteAddr: c.GetAttributes().GetSource().GetAddress().GetSocketAddress().GetAddress() + ":" + fmt.Sprint(c.GetAttributes().GetSource().GetAddress().GetSocketAddress().GetPortValue()),
	}

	for k, v := range c.GetAttributes().GetRequest().GetHttp().GetHeaders() {
		r.Request.Header.Add(k, v)
	}

	r.ID = c.GetAttributes().GetRequest().GetHttp().GetId()
	r.Context = c.GetAttributes().GetContextExtensions()

	return r
}

// FromV3 initializes a Request from a v3 CheckRequest.
func (r *Request) FromV3(c *CheckRequestV3) *Request {
	r.Request = http.Request{
		URL: &url.URL{
			Scheme:   c.GetAttributes().GetRequest().GetHttp().GetScheme(),
			Host:     c.GetAttributes().GetRequest().GetHttp().GetHost(),
			Path:     c.GetAttributes().GetRequest().GetHttp().GetPath(),
			RawQuery: c.GetAttributes().GetRequest().GetHttp().GetQuery(),
			Fragment: c.GetAttributes().GetRequest().GetHttp().GetFragment(),
		},
		Header: http.Header{},
		Method: c.GetAttributes().GetRequest().GetHttp().GetMethod(),
		Proto:  c.GetAttributes().GetRequest().GetHttp().GetProtocol(),
		RemoteAddr: c.GetAttributes().GetSource().GetAddress().GetSocketAddress().GetAddress() + ":" + fmt.Sprint(c.GetAttributes().GetSource().GetAddress().GetSocketAddress().GetPortValue()),
	}

	for k, v := range c.GetAttributes().GetRequest().GetHttp().GetHeaders() {
		r.Request.Header.Add(k, v)
	}

	r.ID = c.GetAttributes().GetRequest().GetHttp().GetId()
	r.Context = c.GetAttributes().GetContextExtensions()

	return r
}

// Response captures the information needed to generate a CheckResponse.
type Response struct {
	Allow    bool
	Response http.Response
}

// AsV2 converts to a v2 CheckResponse.
func (r *Response) AsV2() *CheckResponseV2 {
	convertHeaders := func(h http.Header) []*envoy_api_v2_core.HeaderValueOption {
		var headers []*envoy_api_v2_core.HeaderValueOption

		for k, v := range h {
			headers = append(headers,
				&envoy_api_v2_core.HeaderValueOption{
					Header: &envoy_api_v2_core.HeaderValue{Key: k, Value: v[0]},
				},
			)
		}

		return headers
	}

	if r.Allow {
		return &CheckResponseV2{
			Status: &status.Status{Code: int32(codes.OK)},
			HttpResponse: &envoy_service_auth_v2.CheckResponse_OkResponse{
				OkResponse: &envoy_service_auth_v2.OkHttpResponse{
					Headers: convertHeaders(r.Response.Header),
				},
			},
		}
	}

	return &CheckResponseV2{
		Status: &status.Status{Code: int32(codes.PermissionDenied)},
		HttpResponse: &envoy_service_auth_v2.CheckResponse_DeniedResponse{
			DeniedResponse: &envoy_service_auth_v2.DeniedHttpResponse{
				Headers: convertHeaders(r.Response.Header),
				Status: &envoy_type.HttpStatus{
					Code: envoy_type.StatusCode(r.Response.StatusCode),
				},
			},
		},
	}
}

// AsV3 converts to a v3 CheckResponse.
func (r *Response) AsV3() *CheckResponseV3 {
	convertHeaders := func(h http.Header) []*envoy_config_core_v3.HeaderValueOption {
		var headers []*envoy_config_core_v3.HeaderValueOption

		for k, v := range h {
			headers = append(headers,
				&envoy_config_core_v3.HeaderValueOption{
					Header: &envoy_config_core_v3.HeaderValue{Key: k, Value: v[0]},
				},
			)
		}

		return headers
	}

	if r.Allow {
		return &CheckResponseV3{
			Status: &status.Status{Code: int32(codes.OK)},
			HttpResponse: &envoy_service_auth_v3.CheckResponse_OkResponse{
				OkResponse: &envoy_service_auth_v3.OkHttpResponse{
					Headers: convertHeaders(r.Response.Header),
				},
			},
		}
	}

	return &CheckResponseV3{
		Status: &status.Status{Code: int32(codes.PermissionDenied)},
		HttpResponse: &envoy_service_auth_v3.CheckResponse_DeniedResponse{
			DeniedResponse: &envoy_service_auth_v3.DeniedHttpResponse{
				Headers: convertHeaders(r.Response.Header),
				Status: &envoy_type_v3.HttpStatus{
					Code: envoy_type_v3.StatusCode(r.Response.StatusCode),
				},
			},
		},
	}
}
