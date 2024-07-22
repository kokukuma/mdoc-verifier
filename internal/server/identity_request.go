package server

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"

	"github.com/kokukuma/mdoc-verifier/openid4vp"
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
