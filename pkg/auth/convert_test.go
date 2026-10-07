package auth

import (
	"context"
	"net/http"
	"testing"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"github.com/stretchr/testify/assert"
)

func headerKeysV3(headers []*envoy_config_core_v3.HeaderValueOption) []string {
	keys := []string{}
	for _, h := range headers {
		keys = append(keys, h.GetHeader().GetKey())
	}
	return keys
}

func TestResponseClientHeadersDependOnDebug(t *testing.T) {
	const careHeader = "X-User-Data"
	accessToken := http.CanonicalHeaderKey(string(CerberusHeaderAccessToken))
	webservice := string(CerberusHeaderWebservice)
	all := []string{ExternalAuthHandlerHeader, CerberusHeaderReasonHeader, accessToken, webservice, careHeader}

	newResponse := func(allow, debug bool) *Response {
		r := generateResponse("", ExtraHeaders{
			string(CerberusHeaderAccessToken): "ns/token",
			webservice:                        "ns/webservice",
			careHeader:                        "user",
		})
		r.Allow = allow
		r.Debug = debug
		return r
	}

	// allowed: upstream always gets everything, the client only gets X-Cerberus-* on debug
	ok := newResponse(true, false).AsV3().GetOkResponse()
	assert.ElementsMatch(t, all, headerKeysV3(ok.GetHeaders()))
	assert.Empty(t, ok.GetResponseHeadersToAdd())

	ok = newResponse(true, true).AsV3().GetOkResponse()
	assert.ElementsMatch(t, all, headerKeysV3(ok.GetHeaders()))
	assert.ElementsMatch(t,
		[]string{CerberusHeaderReasonHeader, accessToken, webservice},
		headerKeysV3(ok.GetResponseHeadersToAdd()))

	// denied: internal X-Cerberus-* headers are hidden unless debug is set
	denied := newResponse(false, false).AsV3().GetDeniedResponse()
	assert.ElementsMatch(t,
		[]string{ExternalAuthHandlerHeader, CerberusHeaderReasonHeader, careHeader},
		headerKeysV3(denied.GetHeaders()))

	denied = newResponse(false, true).AsV3().GetDeniedResponse()
	assert.ElementsMatch(t, all, headerKeysV3(denied.GetHeaders()))

	// v2 denied responses are filtered the same way
	assert.Len(t, newResponse(false, false).AsV2().GetDeniedResponse().GetHeaders(), 3)
	assert.Len(t, newResponse(false, true).AsV2().GetDeniedResponse().GetHeaders(), len(all))
}

func TestCheckSetsDebugFromRequestHeader(t *testing.T) {
	authenticator := &Authenticator{}
	for header, expected := range map[string]bool{"": false, "1": true} {
		request := &Request{Context: map[string]string{}, Request: http.Request{Header: http.Header{}}}
		if header != "" {
			// envoy sends lower-case header names
			request.Request.Header.Add("x-cerberus-debug", header)
		}
		response, err := authenticator.Check(context.Background(), request)
		assert.NoError(t, err)
		assert.Equal(t, expected, response.Debug)
	}
}
