package server

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"

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
	Protocol   string   `json:"protocol"`
	Attributes []string `json:"attributes,omitempty"`
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

func CredentialRequirement(attributes []string) (*document.CredentialRequirement, error) {
	// Default attributes if none provided
	if len(attributes) == 0 {
		attributes = []string{"family_name", "given_name", "birth_date", "issuing_country"}
	}

	// Create the elements slice based on provided attributes
	elements := make([]mdoc.ElementIdentifier, 0, len(attributes)+1) // +1 for ageOver if needed

	// Map attribute names to the corresponding element identifiers
	for _, attr := range attributes {
		switch attr {
		case "family_name":
			elements = append(elements, document.IsoFamilyName)
		case "given_name":
			elements = append(elements, document.IsoGivenName)
		case "birth_date":
			elements = append(elements, document.IsoBirthDate)
		case "expiry_date":
			elements = append(elements, document.IsoExpiryDate)
		case "issuing_country":
			elements = append(elements, document.IsoIssuingCountry)
		case "issuing_authority":
			elements = append(elements, document.IsoIssuingAuthority)
		case "document_number":
			elements = append(elements, document.IsoDocumentNumber)
			// Add more cases as needed
		}
	}

	// Always include age verification
	// ageOver20, err := document.AgeOver(20)
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to create age over : %w", err)
	// }
	// elements = append(elements, ageOver20)

	mDLCred, err := document.NewCredential(
		"mDL-request",
		document.IsoMDL,
		document.ISO1801351,
		elements,
		document.WithLimitDisclosure("required"),
		document.WithPurpose("For KYC"),
		document.WithAlgorithms("ES256"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create credential : %w", err)
	}

	CredentialRequirement := document.CredentialRequirement{
		CredentialType: document.CredentialTypeMDOC,
		Credentials: []document.Credential{
			*mDLCred,
		},
	}
	return &CredentialRequirement, nil
}

func (s *Server) GetIdentityRequest(w http.ResponseWriter, r *http.Request) {
	req := GetRequest{}
	if err := parseJSON(r, &req); err != nil {
		jsonErrorResponse(w, fmt.Errorf("failed to parse request: %v", err), http.StatusBadRequest)
		return
	}

	credReq, err := CredentialRequirement(req.Attributes)
	if err != nil {
		jsonErrorResponse(w, fmt.Errorf("failed to parse request: %v", err), http.StatusBadRequest)
		return
	}

	// create session
	// Just use applePrivateKeyPath as reciever private key for preview as well.
	session, err := s.sessions.NewSession(applePrivateKeyPath, credReq)
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

	// 3. verify mdoc device response;
	var resp VerifyResponse

	for _, cred := range session.CredentialRequirement.Credentials {
		doc, err := getVerifiedDoc(devResp, cred.DocType, sessTrans, req.Protocol)
		if err != nil {
			fmt.Printf("failed to get doc: %s: %v", cred.DocType, err)
			continue
		}

		for _, elemName := range cred.ElementIdentifier {
			elemValue, err := doc.GetElementValue(cred.Namespace, elemName)
			if err != nil {
				log.Printf("element not found: %s: %v", elemName, err)
				continue
			}
			resp.Elements = append(resp.Elements, Element{
				NameSpace:  cred.Namespace,
				Identifier: elemName,
				Value:      elemValue,
			})
			log.Printf("element name=%s, value=%s", elemName, elemValue)
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

type ErrorResponse struct {
	Error string `json:"error"`
}

func jsonResponse(w http.ResponseWriter, d interface{}, statusCode int) {
	writeJSONResponse(w, d, statusCode)
}

func jsonErrorResponse(w http.ResponseWriter, err error, statusCode int) {
	errResp := ErrorResponse{
		Error: err.Error(),
	}
	writeJSONResponse(w, errResp, statusCode)
}

func writeJSONResponse(w http.ResponseWriter, data interface{}, statusCode int) {
	w.Header().Set("Content-Type", "application/json")

	dj, err := json.Marshal(data)
	if err != nil {
		log.Printf("JSON marshaling error: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		errResp := ErrorResponse{
			Error: "Internal server error occurred",
		}
		if jsonErr := json.NewEncoder(w).Encode(errResp); jsonErr != nil {
			log.Printf("Failed to write error response: %v", jsonErr)
		}
		return
	}

	w.WriteHeader(statusCode)

	if _, err := io.WriteString(w, string(dj)); err != nil {
		log.Printf("Failed to write response: %v", err)
	}

	log.Printf("Response [%d]: %s", statusCode, string(dj))
}
