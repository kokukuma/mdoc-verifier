package server

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"

	"github.com/kokukuma/mdoc-verifier/credential_data"
	doc "github.com/kokukuma/mdoc-verifier/document"
	"github.com/kokukuma/mdoc-verifier/openid4vp"
	"github.com/kokukuma/mdoc-verifier/pkg/pki"
)

func BeginIdentityRequestOpenID4VP(clientID string) (*openid4vp.AuthorizationRequest, *SessionData, error) {
	nonce, err := CreateNonce()
	if err != nil {
		return nil, nil, err
	}

	curve := ecdh.P256()

	privKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generateKey: %v", err)
	}

	idReq := &openid4vp.AuthorizationRequest{
		ClientID:       clientID,
		ClientIDScheme: "web-origin",
		ResponseType:   "vp_token",
		Nonce:          nonce.String(),

		// TODO: eu.europa.ec.eudi.pid.1 のぶんで動かないかも
		PresentationDefinition: openid4vp.CreatePresentationDefinition(),
	}

	return idReq, &SessionData{
		Nonce:      nonce,
		PrivateKey: privKey,
	}, nil
}

func BeginIdentityRequest() (*credential_data.IdentityRequest, *SessionData, error) {
	nonce, err := CreateNonce()
	if err != nil {
		return nil, nil, err
	}

	curve := ecdh.P256()

	privKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generateKey: %v", err)
	}

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
		Nonce:           nonce.String(),
		ReaderPublicKey: b64.EncodeToString(privKey.PublicKey().Bytes()),
	}

	return idReq, &SessionData{
		Nonce:      nonce,
		PrivateKey: privKey,
	}, nil
}

func BeginIdentityRequestApple(privateKeyPath string) (*credential_data.IdentityRequest, *SessionData, error) {
	privKey, err := pki.LoadPrivateKey(privateKeyPath)
	if err != nil {
		return nil, nil, err
	}
	nonce, err := CreateNonce()
	if err != nil {
		return nil, nil, err
	}
	idReq := credential_data.IdentityRequest{
		Nonce: nonce.String(),
	}
	sessionData := &SessionData{
		Nonce:      nonce,
		PrivateKey: privKey,
	}
	return &idReq, sessionData, nil
}
