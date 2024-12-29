package server

import (
	"github.com/kokukuma/mdoc-verifier/apple_hpke"
	"github.com/kokukuma/mdoc-verifier/document"
	doc "github.com/kokukuma/mdoc-verifier/document"
	"github.com/kokukuma/mdoc-verifier/mdoc"
	"github.com/kokukuma/mdoc-verifier/openid4vp"
	"github.com/kokukuma/mdoc-verifier/pkg/hash"
	"github.com/kokukuma/mdoc-verifier/preview_hpke"
)

func createIDReq(req GetRequest, session *Session) interface{} {
	var idReq interface{}
	switch req.Protocol {
	case "preview":
		// MEMO: previewが生き残るのかどうか不明.
		// エージさんのブログではopenid4vpだけしか言われてなかったし、消えそうな気はする
		idReq = &document.IdentityRequest{
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
		// MEMO: Appleは実質Nonceだけだからそれほど気にしてないと言えばない.
		idReq = &document.IdentityRequest{
			Nonce: session.Nonce.String(),
		}
	}
	return idReq
}

// TODO: SessionTranscriptの作成は、一つのpackageにまとめた方がいいか？
func getSessionTranscript(req VerifyRequest, session *Session) ([]byte, error) {
	var sessTrans []byte
	var err error

	switch req.Protocol {
	case "openid4vp":
		// package nameはclientから取得するようにするか？
		sessTrans, err = preview_hpke.SessionTranscript(session.GetNonceByte(), "com.android.mdl.appreader", hash.Digest([]byte("digital-credentials.dev"), "SHA-256"))
		if req.Origin != "" {
			sessTrans, err = openid4vp.SessionTranscriptBrowser(session.GetNonceByte(), req.Origin, hash.Digest([]byte("digital-credentials.dev"), "SHA-256"))
		}
	case "preview":
		// package nameはclientから取得するようにするか？
		sessTrans, err = preview_hpke.SessionTranscript(session.GetNonceByte(), "com.android.mdl.appreader", session.GetPublicKeyHash())
		if req.Origin != "" {
			sessTrans, err = openid4vp.SessionTranscriptBrowser(session.GetNonceByte(), req.Origin, session.GetPublicKeyHash())
		}
	case "apple":
		sessTrans, err = apple_hpke.SessionTranscript(merchantID, teamID, session.GetNonceByte(), session.GetPublicKeyHash())
	}
	if err != nil {
		return nil, err
	}
	return sessTrans, nil
}

// TODO: 復号とParseは別にした方がいいな
func parseDeviceResponse(req VerifyRequest, session *Session, sessTrans []byte) (*mdoc.DeviceResponse, error) {
	var devResp *mdoc.DeviceResponse
	var err error

	// TODO: 復号とParseは別にした方がいいな
	switch req.Protocol {
	case "openid4vp":
		devResp, err = openid4vp.ParseDataToDeviceResp(req.Data)
	case "preview":
		devResp, err = preview_hpke.ParseDataToDeviceResp(req.Data, session.GetPrivateKey(), sessTrans)
	case "apple":
		// This base64URL encoding is not in any spec, just depends on a client implementation.
		decoded, err := b64.DecodeString(req.Data)
		if err == nil {
			devResp, err = apple_hpke.ParseDataToDeviceResp(decoded, session.GetPrivateKey(), sessTrans)
		}
	}
	if err != nil {
		return nil, err
	}
	return devResp, nil
}

func getVerifiedDoc(devResp *mdoc.DeviceResponse, docType doc.DocType, sessTrans []byte, options []mdoc.VerifierOption) (*mdoc.Document, error) {
	doc, err := devResp.GetDocument(docType)
	if err != nil {
		return nil, err
	}

	// set verifier options mainly because there is no legitimate wallet for now.
	if err := mdoc.NewVerifier(roots, options...).Verify(doc, sessTrans); err != nil {
		return nil, err
	}
	return &doc, nil
}
