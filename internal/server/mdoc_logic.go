package server

import (
	"crypto/sha256"

	"github.com/kokukuma/mdoc-verifier/decoder"
	"github.com/kokukuma/mdoc-verifier/decoder/openid4vp"
	doc "github.com/kokukuma/mdoc-verifier/document"
	"github.com/kokukuma/mdoc-verifier/mdoc"
	"github.com/kokukuma/mdoc-verifier/session_transcript"
)

type IdentityRequest struct {
	Selector        doc.Selector `json:"selector"`
	Nonce           string       `json:"nonce"`
	ReaderPublicKey string       `json:"readerPublicKey"`
}

func createIDReq(req GetRequest, session *Session) interface{} {
	var idReq interface{}
	switch req.Protocol {
	case "preview":
		// MEMO: Unclear if preview will survive.
		// Ege's blog only mentioned openid4vp, and I think it's going to disappear.
		idReq = &IdentityRequest{
			Selector:        RequiredElements.Selector()[0], // Identity Credential API only accept single selector ... ?
			Nonce:           session.Nonce.String(),
			ReaderPublicKey: b64.EncodeToString(session.PrivateKey.PublicKey().Bytes()),
		}
	case "openid4vp":
		idReq = &openid4vp.AuthorizationRequest{
			ClientID:               "digital-credentials.dev",
			ClientIDScheme:         "web-origin",
			ResponseType:           "vp_token",
			Nonce:                  session.Nonce.String(),
			PresentationDefinition: RequiredElements.PresentationDefinition("mDL-request-demo"),
		}
	case "apple":
		// MEMO: Apple is practically only Nonce so I wouldn't say they care that much.
		idReq = &IdentityRequest{
			Nonce: session.Nonce.String(),
		}
	}
	return idReq
}

func getSessionTranscript(req VerifyRequest, session *Session) ([]byte, error) {
	var sessTrans []byte
	var err error

	switch req.Protocol {
	case "openid4vp":
		hash := sha256.Sum256([]byte("digital-credentials.dev"))

		// The request came from native app.
		sessTrans, err = session_transcript.AndroidHandoverV1(session.GetNonceByte(), "com.android.mdl.appreader", hash[:])

		// The request came from browser app.
		if req.Origin != "" {
			sessTrans, err = session_transcript.BrowserHandoverV1(session.GetNonceByte(), req.Origin, hash[:])
		}
	case "preview":
		// The request came from native app.
		sessTrans, err = session_transcript.AndroidHandoverV1(session.GetNonceByte(), "com.android.mdl.appreader", session.GetPublicKeyHash())

		// The request came from browser app.
		if req.Origin != "" {
			sessTrans, err = session_transcript.BrowserHandoverV1(session.GetNonceByte(), req.Origin, session.GetPublicKeyHash())
		}
	case "apple":
		// The request came from iOS app.
		sessTrans, err = session_transcript.AppleHandoverV1(merchantID, teamID, session.GetNonceByte(), session.GetPublicKeyHash())
	}
	if err != nil {
		return nil, err
	}
	return sessTrans, nil
}

func parseDeviceResponse(req VerifyRequest, session *Session, sessTrans []byte) (*mdoc.DeviceResponse, error) {
	var devResp *mdoc.DeviceResponse
	var err error

	switch req.Protocol {
	case "openid4vp":
		devResp, err = decoder.OpenID4VP(req.Data)
	case "preview":
		devResp, err = decoder.AndroidHPKE(req.Data, session.GetPrivateKey(), sessTrans)
	case "apple":
		// This base64URL encoding is not in any spec, just depends on a client implementation.
		decoded, err := b64.DecodeString(req.Data)
		if err != nil {
			return nil, err
		}
		devResp, err = decoder.AppleHPKE(decoded, session.GetPrivateKey(), sessTrans)
	}
	if err != nil {
		return nil, err
	}
	return devResp, nil
}

func verifierOptionsForDevelopment(protocol string) []mdoc.VerifierOption {
	var verifierOptions []mdoc.VerifierOption

	switch protocol {
	case "openid4vp", "preview":
		verifierOptions = []mdoc.VerifierOption{
			// mdoc.WithSkipSignedDateValidation(),
			// mdoc.WithSkipVerifyCertificate(),
		}
	case "apple":
		verifierOptions = []mdoc.VerifierOption{
			mdoc.WithSkipVerifyDeviceSigned(),
			mdoc.WithSkipVerifyCertificate(),
			mdoc.WithSkipVerifyIssuerAuth(),
		}
	}
	return verifierOptions
}

func getVerifiedDoc(devResp *mdoc.DeviceResponse, docType doc.DocType, sessTrans []byte, protocol string) (*mdoc.Document, error) {
	doc, err := devResp.GetDocument(docType)
	if err != nil {
		return nil, err
	}
	options := verifierOptionsForDevelopment(protocol)

	// set verifier options mainly because there is no legitimate wallet for now.
	if err := mdoc.NewVerifier(roots, options...).Verify(doc, sessTrans); err != nil {
		return nil, err
	}
	return doc, nil
}
