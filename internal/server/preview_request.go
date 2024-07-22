package server

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"

	"github.com/kokukuma/mdoc-verifier/credential_data"
	doc "github.com/kokukuma/mdoc-verifier/document"
)

func BeginIdentityRequest(options ...IdentityRequestOption) (*credential_data.IdentityRequest, *SessionData, error) {
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
			Fields:    []credential_data.Field{},
		},
		Nonce:           nonce.String(),
		ReaderPublicKey: b64.EncodeToString(privKey.PublicKey().Bytes()),
	}

	for _, option := range options {
		option(idReq)
	}

	return idReq, &SessionData{
		Nonce:      nonce,
		PrivateKey: privKey,
	}, nil
}

type IdentityRequestOption func(*credential_data.IdentityRequest)

func WithRetention(retention int) IdentityRequestOption {
	return func(ir *credential_data.IdentityRequest) {
		ir.Selector.Retention = credential_data.Retention{Days: retention}
	}
}

func WithFormat(format []string) IdentityRequestOption {
	return func(ir *credential_data.IdentityRequest) {
		ir.Selector.Format = format
	}
}

func WithDocType(docType string) IdentityRequestOption {
	return func(ir *credential_data.IdentityRequest) {
		ir.Selector.DocType = docType
	}
}

func AddField(ns doc.NameSpace, id doc.ElementIdentifier, retain bool) IdentityRequestOption {
	return func(ir *credential_data.IdentityRequest) {
		ir.Selector.Fields = append(ir.Selector.Fields, credential_data.Field{
			Namespace:      ns,
			Name:           id,
			IntentToRetain: retain,
		})
	}
}
