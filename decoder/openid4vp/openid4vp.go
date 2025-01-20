package openid4vp

import (
	"encoding/base64"
	"fmt"

	"github.com/kokukuma/mdoc-verifier/document"
)

var (
	b64 = base64.URLEncoding.WithPadding(base64.StdPadding)
)

// https://openid.net/specs/openid-4-verifiable-presentations-1_0.html

type AuthorizationRequest struct {
	ClientID               string                          `json:"client_id"`
	ClientIDScheme         string                          `json:"client_id_scheme"`
	ResponseType           string                          `json:"response_type"`
	Nonce                  string                          `json:"nonce,omitempty"`
	PresentationDefinition document.PresentationDefinition `json:"presentation_definition,omitempty"`
	DCQLQuery              document.DCQLQuery              `json:"dcql_query,omitempty"`
	ResponseURI            string                          `json:"response_uri,omitempty"`
	ResponseMode           string                          `json:"response_mode,omitempty"`
	Scope                  string                          `json:"scope,omitempty"`
	State                  string                          `json:"state,omitempty"`
	ClientMetadata         ClientMetadata                  `json:"client_metadata,omitempty"`
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

func CreateClientMetadata(serverDomain string) ClientMetadata {
	return ClientMetadata{
		AuthorizationEncryptedResopnseAlg: "ECDH-ES",
		AuthorizationEncryptedResopnseEnc: "A128CBC-HS256",
		IDTokenEncryptedResponseAlg:       "RSA-OAEP-256",
		IDTokenEncryptedResponseEnc:       "A128CBC-HS256",
		JwksURI:                           fmt.Sprintf("https://%s/wallet/jwks.json", serverDomain),
		SubjectSyntaxTypesSupported:       []string{"urn:ietf:params:oauth:jwk-thumbprint"},
		IDTokenSignedResponseAlg:          "RS256",
	}
}
