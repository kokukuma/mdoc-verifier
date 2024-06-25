package openid4vp

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"

	"github.com/kokukuma/identity-credential-api-demo/internal/mdoc"
	"github.com/kokukuma/identity-credential-api-demo/internal/protocol"
)

func BeginIdentityRequest(clientID string) (*IdentityRequestOpenID4VP, *protocol.SessionData, error) {
	nonce, err := protocol.CreateNonce()
	if err != nil {
		return nil, nil, err
	}

	curve := ecdh.P256()

	privKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generateKey: %v", err)
	}

	idReq := &IdentityRequestOpenID4VP{
		ClientID:       clientID,
		ClientIDScheme: "web-origin",
		ResponseType:   "vp_token",
		Nonce:          nonce.String(),
		PresentationDefinition: PresentationDefinition{
			ID: "mDL-request-demo",
			InputDescriptors: []InputDescriptor{
				{
					ID: "org.iso.18013.5.1.mDL",
					Format: Format{
						MsoMdoc: MsoMdoc{
							Alg: []string{"ES256"},
						},
					},
					Constraints: Constraints{
						LimitDisclosure: "required",
						Fields: convPathField(
							mdoc.FamilyName,
							mdoc.GivenName,
						),
					},
				},
			},
		},
	}

	return idReq, &protocol.SessionData{
		Nonce:      nonce,
		PrivateKey: privKey,
	}, nil
}

func convPathField(fs ...mdoc.Element) []PathField {
	result := []PathField{}

	for _, f := range fs {
		result = append(result, PathField{
			Path:           []string{fmt.Sprintf("$['%s']['%s']", f.Namespace, f.Name)},
			IntentToRetain: false,
		})
	}
	return result
}
