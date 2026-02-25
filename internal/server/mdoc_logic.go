package server

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"log"

	"github.com/kokukuma/mdoc-verifier/decoder"
	"github.com/kokukuma/mdoc-verifier/decoder/mdocapi"
	"github.com/kokukuma/mdoc-verifier/decoder/openid4vp"
	"github.com/kokukuma/mdoc-verifier/document"
	"github.com/kokukuma/mdoc-verifier/mdoc"
	"github.com/kokukuma/mdoc-verifier/session_transcript"
)

type IdentityRequest struct {
	Selector        document.Selector `json:"selector"`
	Nonce           string            `json:"nonce"`
	ReaderPublicKey string            `json:"readerPublicKey"`
}

func createIDReq(req GetRequest, session *Session, origin string, sigKey *ecdsa.PrivateKey, certChain []string) interface{} {
	log.Printf("createIDReq: protocol=%s, origin=%s", req.Protocol, origin)
	var idReq interface{}
	switch req.Protocol {
	case "preview":
		// MEMO: Unclear if preview will survive.
		// Ege's blog only mentioned openid4vp, and I think it's going to disappear.
		idReq = &IdentityRequest{
			Selector:        session.CredentialRequirement.Selector()[0], // Identity Credential API only accept single selector ... ?
			Nonce:           session.Nonce.String(),
			ReaderPublicKey: b64.EncodeToString(session.PrivateKey.PublicKey().Bytes()),
		}
	case "openid4vp":
		idReq = &openid4vp.AuthorizationRequest{
			ClientID:               "digital-credentials.dev",
			ClientIDScheme:         "web-origin",
			ResponseType:           "vp_token",
			Nonce:                  session.Nonce.String(),
			PresentationDefinition: session.CredentialRequirement.PresentationDefinition(),
			// DCQLQuery:              session.CredentialRequirement.DCQLQuery(),
		}
	case "apple":
		// MEMO: Apple is practically only Nonce so I wouldn't say they care that much.
		idReq = &IdentityRequest{
			Nonce: session.Nonce.String(),
		}
	case "org-iso-mdoc":
		// ISO/IEC 18013-7 Annex C - DC API with mdoc
		// Check if signing is requested (default: false for now to simplify debugging)
		signRequest := false
		useV11 := false
		if req.Parameters != nil {
			if val, ok := req.Parameters["sign_request"].(bool); ok {
				signRequest = val
			}
			if val, ok := req.Parameters["use_v11"].(bool); ok {
				useV11 = val
			}
		}

		log.Printf("org-iso-mdoc: signRequest=%v, useV11=%v", signRequest, useV11)
		log.Printf("org-iso-mdoc: CredentialRequirement=%+v", session.CredentialRequirement)
		log.Printf("org-iso-mdoc: Credentials count=%d", len(session.CredentialRequirement.Credentials))

		// Convert credentials to DocRequestInput
		docRequests := make([]mdocapi.DocRequestInput, 0, len(session.CredentialRequirement.Credentials))
		for _, cred := range session.CredentialRequirement.Credentials {
			log.Printf("org-iso-mdoc: Converting credential: DocType=%s, Namespace=%s, Elements=%v",
				cred.DocType, cred.Namespace, cred.ElementIdentifier)
			docRequests = append(docRequests, mdocapi.ConvertCredentialToDocRequest(
				cred.DocType,
				cred.Namespace,
				cred.ElementIdentifier,
				true, // intentToRetain: always true for org-iso-mdoc
			))
		}

		// Prepare reader key for signing (nil if unsigned)
		var readerKey *ecdsa.PrivateKey
		var readerCertChain []string
		if signRequest && sigKey != nil {
			readerKey = sigKey
			readerCertChain = certChain
		}

		var mdocReq *mdocapi.MdocAPIRequest
		var encryptionInfo []byte
		var err error

		if useV11 {
			// Version 1.1 (Apple DC API compatible)
			// Use 32-byte nonce for version 1.1
			nonce32 := session.GetNonceByte()[:32]
			log.Printf("org-iso-mdoc: Creating V1.1 request with %d docRequests, origin=%s, signRequest=%v", len(docRequests), origin, signRequest)
			mdocReq, encryptionInfo, err = mdocapi.CreateFullRequestV11(
				nonce32,
				session.GetPublicKey(),
				origin,
				docRequests,
				readerKey,
				readerCertChain,
			)
		} else {
			// Version 1.0 (original)
			// Use 16-byte nonce for version 1.0
			nonce16 := session.GetNonceByte()[:16]
			log.Printf("org-iso-mdoc: Creating V1.0 request with %d docRequests, origin=%s, signRequest=%v", len(docRequests), origin, signRequest)
			mdocReq, encryptionInfo, err = mdocapi.CreateFullRequest(
				nonce16,
				session.GetPublicKey(),
				origin,
				docRequests,
				readerKey,
				readerCertChain,
			)
		}

		if err != nil {
			log.Printf("org-iso-mdoc: Failed to create request: %v", err)
			return nil
		}
		log.Printf("org-iso-mdoc: Request created successfully, encryptionInfo length=%d", len(encryptionInfo))

		// Store encryptionInfo in session for later use
		session.EncryptionInfo = encryptionInfo

		idReq = mdocReq
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
	case "org-iso-mdoc":
		// ISO/IEC 18013-7 Annex C - DC API with mdoc
		// Use the stored encryptionInfo from the session to reconstruct the session transcript
		if len(session.EncryptionInfo) == 0 {
			return nil, err
		}
		sessTrans, err = session_transcript.DcapiHandover(session.EncryptionInfo, req.Origin)
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
	case "org-iso-mdoc":
		// ISO/IEC 18013-7 Annex C - DC API with mdoc
		devResp, err = decoder.MdocAPI(req.Data, session.GetPrivateKey(), sessTrans)
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
	case "org-iso-mdoc":
		// Skip certificate verification for development (wallet's issuer CA not in our pool)
		verifierOptions = []mdoc.VerifierOption{
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

func getVerifiedDoc(devResp *mdoc.DeviceResponse, docType mdoc.DocType, sessTrans []byte, protocol string, certPool *x509.CertPool) (*mdoc.Document, error) {
	doc, err := devResp.GetDocument(docType)
	if err != nil {
		return nil, err
	}
	options := verifierOptionsForDevelopment(protocol)

	// set verifier options mainly because there is no legitimate wallet for now.
	if err := mdoc.NewVerifier(certPool, options...).Verify(doc, sessTrans); err != nil {
		return nil, err
	}
	return doc, nil
}
