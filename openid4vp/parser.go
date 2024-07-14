package openid4vp

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/fxamacker/cbor/v2"
	"github.com/kokukuma/identity-credential-api-demo/mdoc"
	"gopkg.in/square/go-jose.v2"
)

func ParseDeviceResponse(
	vpData *OpenID4VPData,
	origin, clientID string,
	nonceByte []byte,
) (*mdoc.DeviceResponse, []byte, error) {

	decoded, err := b64.DecodeString(vpData.VPToken)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode base64")
	}

	var claims mdoc.DeviceResponse
	if err := cbor.Unmarshal(decoded, &claims); err != nil {
		return nil, nil, fmt.Errorf("failed to parse data as JSON")
	}

	// For EUDIW
	sessTrans, err := generateOID4VPSessionTranscript(nonceByte, clientID, "https://fido-kokukuma.jp.ngrok.io/wallet/direct_post", vpData.APU)

	// For browser
	// sessTrans, err := generateBrowserSessionTranscript(nonceByte, origin, protocol.Digest([]byte(clientID), "SHA-256"))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create session transcript: %v", err)
	}

	return &claims, sessTrans, nil
}

func ParseVPTokenResponse(data string) (*OpenID4VPData, error) {
	var msg OpenID4VPData
	if err := json.Unmarshal([]byte(data), &msg); err != nil {
		return nil, fmt.Errorf("failed to parse data as JSON")
	}
	return &msg, nil
}

func ParseDirectPostJWT(r *http.Request, encKey *ecdsa.PrivateKey) (*OpenID4VPData, error) {
	response, state, err := extractResponseAndState(r)
	if err != nil {
		return nil, err
	}

	jwe, err := jose.ParseEncrypted(response)
	if err != nil {
		return nil, err
	}

	decrypted, err := jwe.Decrypt(encKey)
	if err != nil {
		return nil, err
	}

	var msg OpenID4VPData
	if err := json.Unmarshal(decrypted, &msg); err != nil {
		return nil, fmt.Errorf("failed to parse data as JSON")
	}
	if msg.State != state {
		return nil, fmt.Errorf("unexpected state value")
	}

	// https://github.com/eu-digital-identity-wallet/eudi-lib-jvm-siop-openid4vp-kt/issues/177
	apu, _ := jwe.Header.ExtraHeaders["apu"].(string)
	apv, _ := jwe.Header.ExtraHeaders["apv"].(string)

	msg.APU = apu
	msg.APV = apv

	return &msg, nil
}

func extractResponseAndState(r *http.Request) (response, state string, err error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return "", "", fmt.Errorf("failed to read request body: %v", err)
	}
	defer r.Body.Close()

	contentType := r.Header.Get("Content-Type")
	if contentType != "application/x-www-form-urlencoded" {
		return "", "", fmt.Errorf("unexpected Content-Type: %s", contentType)
	}

	values, err := url.ParseQuery(string(body))
	if err != nil {
		return "", "", fmt.Errorf("failed to parse query: %v", err)
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
