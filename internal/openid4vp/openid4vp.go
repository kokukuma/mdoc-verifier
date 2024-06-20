package openid4vp

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/kokukuma/identity-credential-api-demo/internal/mdoc"
)

var (
	b64 = base64.URLEncoding.WithPadding(base64.StdPadding)
)

// https://openid.net/specs/openid-4-verifiable-presentations-1_0.html

type IdentityRequestOpenID4VP struct {
	ClientID               string                 `json:"client_id"`
	ClientIDScheme         string                 `json:"client_id_scheme"`
	ResponseType           string                 `json:"resopnse_type"`
	Nonce                  string                 `json:"nonce"`
	PresentationDefinition PresentationDefinition `json:"presentation_definition"`
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
	VPToken string `json:"vp_token"`
}

func ParseOpenID4VP(data string) (*mdoc.DeviceResponse, error) {
	var msg OpenID4VPData
	if err := json.Unmarshal([]byte(data), &msg); err != nil {
		return nil, fmt.Errorf("failed to parse data as JSON")
	}

	decoded, err := b64.DecodeString(msg.VPToken)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64")
	}

	var claims mdoc.DeviceResponse
	if err := cbor.Unmarshal(decoded, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse data as JSON")
	}

	return &claims, nil
}
