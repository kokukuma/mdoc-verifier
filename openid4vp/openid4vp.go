package openid4vp

import (
	"encoding/base64"

	cf "github.com/kokukuma/mdoc-verifier/credential_data"
)

var (
	b64 = base64.URLEncoding.WithPadding(base64.StdPadding)
)

// https://openid.net/specs/openid-4-verifiable-presentations-1_0.html

type AuthorizationRequest struct {
	ClientID               string                    `json:"client_id"`
	ClientIDScheme         string                    `json:"client_id_scheme"`
	ResponseType           string                    `json:"response_type"`
	Nonce                  string                    `json:"nonce"`
	PresentationDefinition cf.PresentationDefinition `json:"presentation_definition"`
	ResponseURI            string                    `json:"response_uri"`
	ResponseMode           string                    `json:"response_mode"`
	Scope                  string                    `json:"scope"`
	State                  string                    `json:"state"`
	ClientMetadata         ClientMetadata            `json:"client_metadata"`
}

type ClientMetadata struct {
	AuthorizationEncryptedResopnseAlg string   `json:"authorization_encrypted_response_alg"`
	AuthorizationEncryptedResopnseEnc string   `json:"authorization_encrypted_response_enc"`
	IDTokenEncryptedResponseAlg       string   `json:"id_token_encrypted_response_alg"`
	IDTokenEncryptedResponseEnc       string   `json:"id_token_encrypted_response_enc"`
	JwksURI                           string   `json:"jwks_uri"`
	SubjectSyntaxTypesSupported       []string `json:"subject_syntax_types_supported"`
	IDTokenSignedResponseAlg          string   `json:"id_token_signed_response_alg"`
}

type AuthorizationResponse struct {
	VPToken                string                 `json:"vp_token"`
	IDToken                string                 `json:"id_token"`
	State                  string                 `json:"state"`
	PresentationSubmission PresentationSubmission `json:"presentation_submission"`
	Audience               string                 `json:"aud"`

	// https://datatracker.ietf.org/doc/html/rfc7518#section-4.6.1.2
	APV string
	APU string
}
type PresentationSubmission struct {
	ID            string      `json:"id"`
	DefinitionID  string      `json:"definition_id"`
	DescriptorMap interface{} `json:"descriptor_map"`
}

func CreateClientMetadata() ClientMetadata {
	return ClientMetadata{
		AuthorizationEncryptedResopnseAlg: "ECDH-ES",
		AuthorizationEncryptedResopnseEnc: "A128CBC-HS256",
		IDTokenEncryptedResponseAlg:       "RSA-OAEP-256",
		IDTokenEncryptedResponseEnc:       "A128CBC-HS256",
		JwksURI:                           "https://fido-kokukuma.jp.ngrok.io/wallet/jwks.json",
		SubjectSyntaxTypesSupported:       []string{"urn:ietf:params:oauth:jwk-thumbprint"},
		IDTokenSignedResponseAlg:          "RS256",
	}
}
