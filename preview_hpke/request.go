package preview_hpke

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"

	"github.com/kokukuma/identity-credential-api-demo/mdoc"
	"github.com/kokukuma/identity-credential-api-demo/protocol"
)

func BeginIdentityRequest(options ...IdentityRequestOption) (*IdentityRequestPreview, *protocol.SessionData, error) {
	nonce, err := protocol.CreateNonce()
	if err != nil {
		return nil, nil, err
	}

	curve := ecdh.P256()

	privKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generateKey: %v", err)
	}

	idReq := &IdentityRequestPreview{
		Selector: Selector{
			Format:    []string{"mdoc"},
			Retention: Retention{Days: 90},
			DocType:   "org.iso.18013.5.1.mDL",
			Fields:    []Field{},
		},
		Nonce:           nonce.String(),
		ReaderPublicKey: b64.EncodeToString(privKey.PublicKey().Bytes()),
	}

	for _, option := range options {
		option(idReq)
	}

	return idReq, &protocol.SessionData{
		Nonce:      nonce,
		PrivateKey: privKey,
	}, nil
}

type IdentityRequestOption func(*IdentityRequestPreview)

func WithRetention(retention int) IdentityRequestOption {
	return func(ir *IdentityRequestPreview) {
		ir.Selector.Retention = Retention{Days: retention}
	}
}

func WithFormat(format []string) IdentityRequestOption {
	return func(ir *IdentityRequestPreview) {
		ir.Selector.Format = format
	}
}

func WithDocType(docType string) IdentityRequestOption {
	return func(ir *IdentityRequestPreview) {
		ir.Selector.DocType = docType
	}
}

func AddField(elem mdoc.Element) IdentityRequestOption {
	return func(ir *IdentityRequestPreview) {
		ir.Selector.Fields = append(ir.Selector.Fields, Field{
			Namespace:      elem.Namespace,
			Name:           elem.Name,
			IntentToRetain: false,
		})
	}
}
