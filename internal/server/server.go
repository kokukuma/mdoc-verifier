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
	"github.com/kokukuma/mdoc-verifier/document"
	"github.com/kokukuma/mdoc-verifier/internal/cryptoroot"
	"github.com/kokukuma/mdoc-verifier/mdoc"
	"github.com/kokukuma/mdoc-verifier/pkg/pki"
)

var (
	roots *x509.CertPool
	b64   = base64.URLEncoding.WithPadding(base64.StdPadding)

	merchantID          = "PassKit_Identity_Test_Merchant_ID"
	teamID              = "PassKit_Identity_Test_Team_ID"
	applePrivateKeyPath = os.Getenv("APPLE_MERCHANT_ENCRYPTION_PRIVATE_KEY_PATH")

	ageOver20, _ = document.AgeOver(20)

	// Which document and elements want to obtain.
	RequiredElements = document.Elements{
		document.IsoMDL: {
			document.ISO1801351: {
				document.IsoFamilyName,
				document.IsoGivenName,
				document.IsoBirthDate,
				document.IsoDocumentNumber,
				ageOver20,
			},
		},
	}
)

func NewServer() *Server {
	serverDomain := os.Getenv("SERVER_DOMAIN")
	if serverDomain == "" {
		panic("SERVER_DOMAIN is not set")
	}
	clientDomain := os.Getenv("CLIENT_DOMAIN")
	if clientDomain == "" {
		panic("CLIENT_DOMAIN is not set")
	}

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
		sessions:     NewSessions(),
		sigKey:       sigKey,
		encKey:       encKey,
		certChain:    certChain,
		serverDomain: serverDomain,
		clientDomain: clientDomain,
	}
}

type Server struct {
	mu           sync.RWMutex
	sessions     *Sessions
	sigKey       *ecdsa.PrivateKey
	encKey       *ecdsa.PrivateKey
	certChain    []string
	serverDomain string
	clientDomain string
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
	NameSpace  mdoc.NameSpace         `json:"namespace"`
	Identifier mdoc.ElementIdentifier `json:"identifier"`
	Value      mdoc.ElementValue      `json:"value"`
}

func (s *Server) GetIdentityRequest(w http.ResponseWriter, r *http.Request) {
	req := GetRequest{}
	if err := parseJSON(r, &req); err != nil {
		jsonErrorResponse(w, fmt.Errorf("failed to parse request: %v", err), http.StatusBadRequest)
		return
	}

	// create session
	// Just use applePrivateKeyPath as reciever private key for preview as well.
	session, err := s.sessions.NewSession(applePrivateKeyPath)
	if err != nil {
		jsonErrorResponse(w, fmt.Errorf("failed to SaveSession: %v", err), http.StatusBadRequest)
		return
	}

	// create request
	idReq := createIDReq(req, session)

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

	// 1. get session_transcript
	sessTrans, err := getSessionTranscript(req, session)
	if err != nil {
		jsonErrorResponse(w, fmt.Errorf("failed to get session transcript: %v", err), http.StatusBadRequest)
		return
	}

	// 2. prase request to mdoc device response
	devResp, err := parseDeviceResponse(req, session, sessTrans)
	if err != nil {
		jsonErrorResponse(w, fmt.Errorf("failed to parse reqest: %v", err), http.StatusBadRequest)
		return
	}
	spew.Dump(devResp)

	// 3. verify mdoc device response;
	var resp VerifyResponse

	for docType, namespaces := range RequiredElements {
		doc, err := getVerifiedDoc(devResp, docType, sessTrans, req.Protocol)
		if err != nil {
			fmt.Printf("failed to get doc: %s: %v", docType, err)
			continue
		}

		for namespace, elemNames := range namespaces {
			for _, elemName := range elemNames {
				elemValue, err := doc.GetElementValue(namespace, elemName)
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
