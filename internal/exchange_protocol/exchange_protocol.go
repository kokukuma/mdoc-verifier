package exchange_protocol

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

var (
	b64 = base64.URLEncoding.WithPadding(base64.StdPadding)
)

type IdentityRequest interface {
	ApplyOption(option IdentityRequestOption)
}

type IdentityRequestOption func(IdentityRequest)

func BeginIdentityRequest(protocol string, options ...IdentityRequestOption) (IdentityRequest, *SessionData, error) {
	nonce, err := CreateNonce()
	if err != nil {
		return nil, nil, err
	}

	curve := ecdh.P256()

	privKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generateKey: %v", err)
	}

	var idReq IdentityRequest

	switch protocol {
	case "openid4vp":
		idReq = &IdentityRequestOpenID4VP{
			ClientID:       "digital-credentials.dev",
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
							Fields: ConvPathField(
								FamilyNameField,
								GivenNameField,
								AgeOver21Field,
							),
						},
					},
				},
			},
		}
	case "preview":
		idReq = &IdentityRequestPreview{
			Selector: Selector{
				Format:    []string{"mdoc"},
				Retention: Retention{Days: 90},
				DocType:   "org.iso.18013.5.1.mDL",
				Fields:    []Field{},
			},
			Nonce:           nonce.String(),
			ReaderPublicKey: b64.EncodeToString(privKey.PublicKey().Bytes()),
		}
	case "apple":
		return nil, nil, fmt.Errorf("not supported yet")
	}

	for _, option := range options {
		option(idReq)
	}

	return idReq, &SessionData{
		Nonce:      nonce,
		PrivateKey: privKey,
	}, nil
}

func WithRetention(retention int) IdentityRequestOption {
	return func(ir IdentityRequest) {
		switch v := ir.(type) {
		case *IdentityRequestPreview:
			v.Selector.Retention = Retention{Days: retention}
		case *IdentityRequestOpenID4VP:
			// v.Selector.Retention = Retention{Days: retention}
		}
	}
}

func WithFormat(format []string) IdentityRequestOption {
	return func(ir IdentityRequest) {
		switch v := ir.(type) {
		case *IdentityRequestPreview:
			v.Selector.Format = format
		case *IdentityRequestOpenID4VP:
			//v.Selector.Format = format
		}
	}
}

func WithDocType(docType string) IdentityRequestOption {
	return func(ir IdentityRequest) {
		switch v := ir.(type) {
		case *IdentityRequestPreview:
			v.Selector.DocType = docType
		case *IdentityRequestOpenID4VP:
			// v.PresentationDefinition .DocType = docType
		}
	}
}

func AddField(field Field) IdentityRequestOption {
	return func(ir IdentityRequest) {
		switch v := ir.(type) {
		case *IdentityRequestPreview:
			v.Selector.Fields = append(v.Selector.Fields, field)
		case *IdentityRequestOpenID4VP:
			// v.Selector.Fields = append(ir.Selector.Fields, field)
		}
	}
}

func AddDescriptor(field Field) IdentityRequestOption {
	return func(ir IdentityRequest) {
		switch v := ir.(type) {
		case *IdentityRequestPreview:
			v.Selector.Fields = append(v.Selector.Fields, field)
		case *IdentityRequestOpenID4VP:
			// v.Selector.Fields = append(ir.Selector.Fields, field)
		}
	}
}
