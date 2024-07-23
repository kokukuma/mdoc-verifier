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
		idReq, err = BeginIdentityRequest(session)
	case "openid4vp":
		idReq, err = BeginIdentityRequestOpenID4VP(session, "digital-credentials.dev")
	case "apple":
		idReq, err = BeginIdentityRequestApple(session)
	}
	if err != nil {
		jsonErrorResponse(w, fmt.Errorf("failed to get BeginIdentityRequest: openid4vp: %v", err), http.StatusBadRequest)
		return
	}

	jsonResponse(w, GetResponse{
		SessionID: session.ID,
		Data:      idReq,
	}, http.StatusOK)

	return
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

	var skipVerification bool

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

	// 2. prase request
	var prasedReq interface{}
	switch req.Protocol {
	case "openid4vp":
		prasedReq, err = openid4vp.ParseVPTokenResponse(req.Data)
	case "preview":
		prasedReq, err = preview_hpke.ParseTokenResponse(req.Data)
	case "apple":
		prasedReq, err = apple_hpke.ParseHPKEEnvelope(req.Data)
	}
	if err != nil {
		jsonErrorResponse(w, fmt.Errorf("failed to parse reqest: %v", err), http.StatusBadRequest)
		return
	}

	// 3. parse mdoc device response
	var devResp *mdoc.DeviceResponse
	switch req.Protocol {
	case "openid4vp":
		devResp, err = openid4vp.ParseDeviceResponse(prasedReq.(*openid4vp.AuthorizationResponse))
	case "preview":
		devResp, err = preview_hpke.ParseDeviceResponse(prasedReq.(*preview_hpke.PreviewData), session.GetPrivateKey(), sessTrans)
	case "apple":
		skipVerification = true
		devResp, err = apple_hpke.ParseDeviceResponse(prasedReq.(*apple_hpke.HPKEEnvelope), session.GetPrivateKey(), sessTrans)
	}
	if err != nil {
		jsonErrorResponse(w, fmt.Errorf("failed to parse mdoc device response: %v", err), http.StatusBadRequest)
		return
	}
	spew.Dump(devResp)

	// 4. verify mdoc device response
	var resp VerifyResponse
	for _, doc := range devResp.Documents {
		if !skipVerification {
			if err := mdoc.Verify(doc, sessTrans, roots, true, false); err != nil {
				jsonErrorResponse(w, fmt.Errorf("failed to verify mdoc: %v", err), http.StatusBadRequest)
				return
			}
		}

		// element取得
		for _, elemName := range []document.ElementIdentifier{
			document.IsoFamilyName,
			document.IsoGivenName,
			document.IsoBirthDate,
			document.IsoDocumentNumber,
		} {
			elemValue, err := doc.IssuerSigned.GetElementValue(document.ISO1801351, elemName)
			if err != nil {
				fmt.Println(err)
				continue
			}
			resp.Elements = append(resp.Elements, Element{
				NameSpace:  document.ISO1801351,
				Identifier: elemName,
				Value:      elemValue,
			})
			spew.Dump(elemName, elemValue)
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
