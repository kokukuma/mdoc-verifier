package server

import (
	"github.com/kokukuma/mdoc-verifier/credential_data"
	doc "github.com/kokukuma/mdoc-verifier/document"
	"github.com/kokukuma/mdoc-verifier/openid4vp"
)

func BeginIdentityRequestOpenID4VP(session *Session, clientID string) (*openid4vp.AuthorizationRequest, error) {
	idReq := &openid4vp.AuthorizationRequest{
		ClientID:               clientID,
		ClientIDScheme:         "web-origin",
		ResponseType:           "vp_token",
		Nonce:                  session.Nonce.String(),
		PresentationDefinition: openid4vp.CreatePresentationDefinition(),
	}
	return idReq, nil
}

func BeginIdentityRequest(session *Session) (*credential_data.IdentityRequest, error) {
	idReq := &credential_data.IdentityRequest{
		Selector: credential_data.Selector{
			Format:    []string{"mdoc"},
			Retention: credential_data.Retention{Days: 90},
			DocType:   "org.iso.18013.5.1.mDL",
			Fields: []credential_data.Field{
				{
					Namespace:      doc.ISO1801351,
					Name:           doc.IsoFamilyName,
					IntentToRetain: false,
				},
				{
					Namespace:      doc.ISO1801351,
					Name:           doc.IsoGivenName,
					IntentToRetain: false,
				},
				{
					Namespace:      doc.ISO1801351,
					Name:           doc.IsoDocumentNumber,
					IntentToRetain: false,
				},
				{
					Namespace:      doc.ISO1801351,
					Name:           doc.IsoBirthDate,
					IntentToRetain: false,
				},
			},
		},
		Nonce:           session.Nonce.String(),
		ReaderPublicKey: b64.EncodeToString(session.PrivateKey.PublicKey().Bytes()),
	}
	return idReq, nil
}

func BeginIdentityRequestApple(session *Session) (*credential_data.IdentityRequest, error) {
	idReq := credential_data.IdentityRequest{
		Nonce: session.Nonce.String(),
	}
	return &idReq, nil
}
