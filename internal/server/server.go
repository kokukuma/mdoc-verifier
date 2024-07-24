package server

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"github.com/davecgh/go-spew/spew"
	"github.com/kokukuma/mdoc-verifier/apple_hpke"
	"github.com/kokukuma/mdoc-verifier/credential_data"
	"github.com/kokukuma/mdoc-verifier/document"
	"github.com/kokukuma/mdoc-verifier/internal/cryptoroot"
	"github.com/kokukuma/mdoc-verifier/mdoc"
	"github.com/kokukuma/mdoc-verifier/openid4vp"
	"github.com/kokukuma/mdoc-verifier/pkg/hash"
	"github.com/kokukuma/mdoc-verifier/pkg/pki"
	"github.com/kokukuma/mdoc-verifier/preview_hpke"
)

var (
	roots *x509.CertPool
	b64   = base64.URLEncoding.WithPadding(base64.StdPadding)

	merchantID          = "PassKit_Identity_Test_Merchant_ID"
	teamID              = "PassKit_Identity_Test_Team_ID"
	applePrivateKeyPath = os.Getenv("APPLE_MERCHANT_ENCRYPTION_PRIVATE_KEY_PATH")
	serverDomain        = os.Getenv("SERVER_DOMAIN")

	// Which document and elements want to obtain.
	RequiredElements = credential_data.Documents{
		document.IsoMDL: {
			document.ISO1801351: {
				document.IsoFamilyName,
				document.IsoGivenName,
				document.IsoBirthDate,
				document.IsoDocumentNumber,
			},
		},
	}
)

func NewServer() *Server {
	dir, err := filepath.Abs(filepath.Dir("."))
	if err != nil {
		panic("failed to load rootCerts: " + err.Error())
	}
	roots, err = pki.GetRootCertificates(filepath.Join(dir, "internal", "server", "pems"))
	if err != nil {
		panic("failed to load rootCerts: " + err.Error())
	}

	sigKey, certChain, err := cryptoroot.GenECDSAKeys()
	if err != nil {
		panic("failed to load rootCerts: " + err.Error())
	}

	encKey, _, err := cryptoroot.GenECDSAKeys()
	if err != nil {
		panic("failed to load rootCerts: " + err.Error())
	}
	return &Server{
		sessions:  NewSessions(),
		sigKey:    sigKey,
		encKey:    encKey,
		certChain: certChain,
	}
}

type Server struct {
	mu        sync.RWMutex
	sessions  *Sessions
	sigKey    *ecdsa.PrivateKey
	encKey    *ecdsa.PrivateKey
	certChain []string
}

type GetRequest struct {
	Protocol string `json:"protocol"`
}

type GetResponse struct {
	SessionID string      `json:"session_id"`
	Data      interface{} `json:"data"`
}

type VerifyRequest struct {
	SessionID string `json:"session_id"`
	Protocol  string `json:"protocol"`
	Data      string `json:"data"`
	Origin    string `json:"origin"`
}

type VerifyResponse struct {
	Elements []Element `json:"elements,omitempty"`
	Error    string    `json:"error,omitempty"`
}

type Element struct {
	NameSpace  document.NameSpace         `json:"namespace"`
	Identifier document.ElementIdentifier `json:"identifier"`
	Value      document.ElementValue      `json:"value"`
}

func (s *Server) GetIdentityRequest(w http.ResponseWriter, r *http.Request) {
	req := GetRequest{}
	if err := parseJSON(r, &req); err != nil {
		jsonErrorResponse(w, fmt.Errorf("failed to parse request: %v", err), http.StatusBadRequest)
		return
	}

	// create session
	// Only apple require to use applePrivateKeyPath, but that can be used for other protocols as well.
	session, err := s.sessions.NewSession(applePrivateKeyPath)
	if err != nil {
		jsonErrorResponse(w, fmt.Errorf("failed to SaveSession: %v", err), http.StatusBadRequest)
		return
	}

	// create request
	var idReq interface{}
	switch req.Protocol {
	case "preview":
		idReq = &credential_data.IdentityRequest{
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
		idReq = &credential_data.IdentityRequest{
			Nonce: session.Nonce.String(),
		}
	}

	jsonResponse(w, GetResponse{
		SessionID: session.ID,
		Data:      idReq,
	}, http.StatusOK)

	return
}

func verifierOptionsForDevelopment(protocol string) []mdoc.VerifierOption {
	var verifierOptions []mdoc.VerifierOption

	switch protocol {
	case "openid4vp":
		verifierOptions = []mdoc.VerifierOption{
			mdoc.AllowSelfCert(),
			mdoc.SkipSignedDateValidation(),
		}
	case "preview":
		verifierOptions = []mdoc.VerifierOption{
			mdoc.AllowSelfCert(),
			mdoc.SkipSignedDateValidation(),
		}
	case "apple":
		verifierOptions = []mdoc.VerifierOption{
			mdoc.SkipVerifyDeviceSigned(),
			mdoc.SkipVerifyCertificate(),
			mdoc.SkipVerifyIssuerAuth(),
			mdoc.SkipValidateCertification(),
		}
	}
	return verifierOptions
}

func (s *Server) VerifyIdentityResponse(w http.ResponseWriter, r *http.Request) {
	req := VerifyRequest{}
	if err := parseJSON(r, &req); err != nil {
		jsonErrorResponse(w, fmt.Errorf("failed to parseJSON: %v", err), http.StatusBadRequest)
		return
	}

	session, err := s.sessions.GetSession(req.SessionID)
	if err != nil {
		jsonErrorResponse(w, fmt.Errorf("failed to GetSession: %v", err), http.StatusBadRequest)
		return
	}

	// 1. get session_transcript
	var sessTrans []byte
	switch req.Protocol {
	case "openid4vp":
		sessTrans, err = openid4vp.SessionTranscriptBrowser(session.GetNonceByte(), req.Origin, hash.Digest([]byte("digital-credentials.dev"), "SHA-256"))
	case "preview":
		sessTrans, err = openid4vp.SessionTranscriptBrowser(session.GetNonceByte(), req.Origin, session.GetPublicKeyHash())
	case "apple":
		sessTrans, err = apple_hpke.SessionTranscript(merchantID, teamID, session.GetNonceByte(), session.GetPublicKeyHash())
	}
	if err != nil {
		jsonErrorResponse(w, fmt.Errorf("failed to get session transcript: %v", err), http.StatusBadRequest)
		return
	}

	// 2. prase request to mdoc device response
	var devResp *mdoc.DeviceResponse

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
		jsonErrorResponse(w, fmt.Errorf("failed to parse reqest: %v", err), http.StatusBadRequest)
		return
	}
	spew.Dump(devResp)

	// 3. verify mdoc device response;
	var resp VerifyResponse

	for docType, namespaces := range RequiredElements {
		doc, err := devResp.GetDocument(docType)
		if err != nil {
			fmt.Printf("document not found: %s", doc.DocType)
			continue
		}

		// set verifier options mainly because there is no legitimate wallet for now.
		if err := mdoc.NewVerifier(roots, verifierOptionsForDevelopment(req.Protocol)...).Verify(doc, sessTrans); err != nil {
			jsonErrorResponse(w, fmt.Errorf("failed to verify mdoc: %v", err), http.StatusBadRequest)
			return
		}

		for namespace, elemNames := range namespaces {
			for _, elemName := range elemNames {
				elemValue, err := doc.IssuerSigned.GetElementValue(namespace, elemName)
				if err != nil {
					fmt.Printf("element not found: %s", elemName)
					continue
				}
				resp.Elements = append(resp.Elements, Element{
					NameSpace:  namespace,
					Identifier: elemName,
					Value:      elemValue,
				})
				spew.Dump(elemName, elemValue)
			}
		}
	}

	jsonResponse(w, resp, http.StatusOK)
}

func parseJSON(r *http.Request, v interface{}) error {
	if r == nil || r.Body == nil {
		return errors.New("No request given")
	}

	defer r.Body.Close()
	defer io.Copy(io.Discard, r.Body)

	err := json.NewDecoder(r.Body).Decode(v)
	if err != nil {
		return err
	}
	return nil
}

func jsonResponse(w http.ResponseWriter, d interface{}, c int) {
	dj, err := json.Marshal(d)
	if err != nil {
		http.Error(w, "Error creating JSON response", http.StatusInternalServerError)
	}
	spew.Dump(dj)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(c)
	fmt.Fprintf(w, "%s", dj)
}

func jsonErrorResponse(w http.ResponseWriter, e error, c int) {
	var resp VerifyResponse
	resp.Error = e.Error()
	dj, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, "Error creating JSON response", http.StatusInternalServerError)
	}
	spew.Dump(dj)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(c)
	fmt.Fprintf(w, "%s", dj)
}
