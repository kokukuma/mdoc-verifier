package decoder

import (
	"crypto/ecdsa"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/fxamacker/cbor/v2"
	"github.com/kokukuma/mdoc-verifier/decoder/openid4vp"
	"github.com/kokukuma/mdoc-verifier/mdoc"
	"gopkg.in/square/go-jose.v2"
)

const (
	formContentType = "application/x-www-form-urlencoded"
)

func AuthzRespOpenID4VP(
	ar *openid4vp.AuthorizationResponse,
) (*mdoc.DeviceResponse, error) {
	if ar == nil {
		return nil, fmt.Errorf("nil authorization response")
	}

	// It must use nopadding ?
	decoded, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(ar.VPToken) // eudiw
	if err != nil {
		decoded, err = base64.URLEncoding.WithPadding(base64.StdPadding).DecodeString(ar.VPToken) // identity credential api ?
		if err != nil {
			return nil, fmt.Errorf("failed to decode base64 token: %w", err)
		}
	}

	var claims mdoc.DeviceResponse
	if err := cbor.Unmarshal(decoded, &claims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal CBOR data: %w", err)
	}
	return &claims, nil
}

func OpenID4VP(data string) (*mdoc.DeviceResponse, error) {
	var msg openid4vp.AuthorizationResponse
	if err := json.Unmarshal([]byte(data), &msg); err != nil {
		return nil, fmt.Errorf("failed to parse authorization response: %w", err)
	}
	return AuthzRespOpenID4VP(&msg)
}

func ParseDirectPostJWT(r *http.Request, encKey *ecdsa.PrivateKey) (*openid4vp.AuthorizationResponse, error) {
	if encKey == nil {
		return nil, fmt.Errorf("nil encryption key")
	}

	response, state, err := extractResponseAndState(r)
	if err != nil {
		return nil, fmt.Errorf("failed to extract response and state: %w", err)
	}

	jwe, err := jose.ParseEncrypted(response)
	if err != nil {
		return nil, fmt.Errorf("failed to parse encrypted response: %w", err)
	}

	decrypted, err := jwe.Decrypt(encKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt response: %w", err)
	}

	var msg openid4vp.AuthorizationResponse
	if err := json.Unmarshal(decrypted, &msg); err != nil {
		return nil, fmt.Errorf("failed to parse decrypted data: %w", err)
	}

	if !secureCompare(msg.State, state) {
		return nil, fmt.Errorf("state mismatch")
	}

	// https://github.com/eu-digital-identity-wallet/eudi-lib-jvm-siop-openid4vp-kt/issues/177
	if apu, ok := jwe.Header.ExtraHeaders["apu"].(string); ok {
		msg.APU = apu
	}
	if apv, ok := jwe.Header.ExtraHeaders["apv"].(string); ok {
		msg.APV = apv
	}

	return &msg, nil
}

func secureCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func extractResponseAndState(r *http.Request) (response, state string, err error) {
	if r == nil {
		return "", "", fmt.Errorf("nil request")
	}

	contentType := strings.ToLower(r.Header.Get("Content-Type"))
	if contentType != strings.ToLower(formContentType) {
		return "", "", fmt.Errorf("invalid content type: %s", contentType)
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return "", "", fmt.Errorf("failed to read request body: %v", err)
	}
	defer r.Body.Close()

	values, err := url.ParseQuery(string(body))
	if err != nil {
		return "", "", fmt.Errorf("failed to parse query: %w", err)
	}

	response = values.Get("response")
	if response == "" {
		return "", "", fmt.Errorf("response parameter is missing")
	}

	state = values.Get("state")
	if state == "" {
		return "", "", fmt.Errorf("state parameter is missing")

	}

	return response, state, nil
}
