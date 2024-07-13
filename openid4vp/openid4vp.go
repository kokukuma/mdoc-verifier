package openid4vp

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/kokukuma/identity-credential-api-demo/mdoc"
	"github.com/kokukuma/identity-credential-api-demo/protocol"
)

var (
	b64 = base64.URLEncoding.WithPadding(base64.StdPadding)
)

// https://openid.net/specs/openid-4-verifiable-presentations-1_0.html

type IdentityRequestOpenID4VP struct {
	ClientID               string                 `json:"client_id"`
	ClientIDScheme         string                 `json:"client_id_scheme"`
	ResponseType           string                 `json:"response_type"`
	Nonce                  string                 `json:"nonce"`
	PresentationDefinition PresentationDefinition `json:"presentation_definition"`
	ResponseURI            string                 `json:"response_uri"`
	ResponseMode           string                 `json:"response_mode"`
	Scope                  string                 `json:"scope"`
	State                  string                 `json:"state"`
	ClientMetadata         ClientMetadata         `json:"client_metadata"`
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

type PresentationDefinition struct {
	ID               string            `json:"id"`
	InputDescriptors []InputDescriptor `json:"input_descriptors"`
}

type InputDescriptor struct {
	ID          string      `json:"id"`
	Format      Format      `json:"format"`
	Constraints Constraints `json:"constraints"`
}

type Constraints struct {
	LimitDisclosure string      `json:"limit_disclosure"`
	Fields          []PathField `json:"fields"`
}

type PathField struct {
	Path           []string `json:"path"`
	IntentToRetain bool     `json:"intent_to_retain"`
}

type Format struct {
	MsoMdoc MsoMdoc `json:"mso_mdoc,omitempty"`
}

type MsoMdoc struct {
	Alg []string `json:"alg"`
}

type OpenID4VPData struct {
	VPToken                string                 `json:"vp_token"`
	State                  string                 `json:"state"`
	PresentationSubmission PresentationSubmission `json:"presentation_submission"`
}
type PresentationSubmission struct {
	ID            string      `json:"id"`
	DefinitionID  string      `json:"definition_id"`
	DescriptorMap interface{} `json:"descriptor_map"`
}

func ParseDeviceResponse(
	data, origin, clientID string,
	nonceByte []byte,
) (*mdoc.DeviceResponse, []byte, error) {
	var msg OpenID4VPData
	if err := json.Unmarshal([]byte(data), &msg); err != nil {
		return nil, nil, fmt.Errorf("failed to parse data as JSON")
	}

	decoded, err := b64.DecodeString(msg.VPToken)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode base64")
	}

	var claims mdoc.DeviceResponse
	if err := cbor.Unmarshal(decoded, &claims); err != nil {
		return nil, nil, fmt.Errorf("failed to parse data as JSON")
	}

	sessTrans, err := generateBrowserSessionTranscript(nonceByte, origin, protocol.Digest([]byte(clientID), "SHA-256"))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create aad: %v", err)
	}

	return &claims, sessTrans, nil
}
