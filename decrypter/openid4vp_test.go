package decrypter

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kokukuma/mdoc-verifier/decrypter/openid4vp"
	"gopkg.in/square/go-jose.v2"
)

func TestAuthzRespOpenID4VP(t *testing.T) {
	ar := &openid4vp.AuthorizationResponse{
		VPToken: "encodedBase64Token",
	}

	_, err := AuthzRespOpenID4VP(ar)
	if err == nil {
		t.Errorf("expected error due to invalid base64 token, got nil")
	}
}

func TestOpenID4VP(t *testing.T) {
	data := `{"VPToken": "encodedBase64Token"}`
	_, err := OpenID4VP(data)
	if err == nil {
		t.Errorf("expected error due to invalid base64 token, got nil")
	}
}

func TestParseDirectPostJWT(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubKey := privKey.Public()

	encrypter, err := jose.NewEncrypter(jose.A128GCM, jose.Recipient{Algorithm: jose.ECDH_ES_A128KW, Key: pubKey}, nil)
	if err != nil {
		t.Fatalf("failed to create encrypter: %v", err)
	}

	payload := "testPayload"
	object, err := encrypter.Encrypt([]byte(payload))
	if err != nil {
		t.Fatalf("failed to encrypt payload: %v", err)
	}

	jwe, err := object.CompactSerialize()
	if err != nil {
		t.Fatalf("failed to serialize JWE: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("response="+jwe+"&state=testState"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := ParseDirectPostJWT(req, privKey)
	if err == nil {
		t.Errorf("expected error due to invalid JWE payload, got nil")
	}
	if resp != nil {
		t.Errorf("expected nil response, got %v", resp)
	}
}

func TestExtractResponseAndState(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("response=testResponse&state=testState"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	response, state, err := extractResponseAndState(req)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if response != "testResponse" {
		t.Errorf("expected response 'testResponse', got %v", response)
	}
	if state != "testState" {
		t.Errorf("expected state 'testState', got %v", state)
	}
}

func TestExtractResponseAndState_InvalidContentType(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("response=testResponse&state=testState"))
	req.Header.Set("Content-Type", "application/json")

	_, _, err := extractResponseAndState(req)
	if err == nil {
		t.Errorf("expected error due to invalid content type, got nil")
	}
}

func TestExtractResponseAndState_MissingParameters(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("response=testResponse"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	_, _, err := extractResponseAndState(req)
	if err == nil {
		t.Errorf("expected error due to missing state parameter, got nil")
	}
}
