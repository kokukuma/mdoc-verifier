package server

import (
	"crypto/ecdsa"
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
)

var (
	b64 = base64.URLEncoding.WithPadding(base64.StdPadding)

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
		panic("failed to get current directory: " + err.Error())
	}

	pemsDir := filepath.Join(dir, "internal", "server", "pems")

	// Initialize certificate manager
	certManager, err := NewCertManager(pemsDir)
	if err != nil {
		panic("failed to initialize certificate manager: " + err.Error())
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
		certManager:  certManager,
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
	certManager  *CertManager // 証明書管理機能
}

type GetRequest struct {
	Protocol   string                 `json:"protocol"`
	Attributes []string               `json:"attributes,omitempty"`
	Parameters map[string]interface{} `json:"parameters,omitempty"` // For additional parameters like cross_device
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
	Elements []Element           `json:"elements,omitempty"`
	Error    string              `json:"error,omitempty"`
	Errors   map[string][]string `json:"errors,omitempty"`
}

type Element struct {
	NameSpace  mdoc.NameSpace         `json:"namespace"`
	Identifier mdoc.ElementIdentifier `json:"identifier"`
	Value      mdoc.ElementValue      `json:"value"`
}

func CredentialRequirement(attributes []string, docTypeStr string) (*document.CredentialRequirement, error) {
	// Determine docType and namespace based on docTypeStr
	var docType mdoc.DocType
	var namespace mdoc.NameSpace
	var credName string
	var elements []mdoc.ElementIdentifier

	switch docTypeStr {
	case "org.iso.23220.1.jp.mnc":
		docType = document.JpMnc
		namespace = document.JPMNC1
		credName = "jp-mnc-request"

		// Japanese My Number Card uses different element names
		// Default attributes if none provided
		if len(attributes) == 0 {
			attributes = []string{"full_name", "birth_date_unicode"}
		}

		elements = make([]mdoc.ElementIdentifier, 0, len(attributes))
		for _, attr := range attributes {
			switch attr {
			case "full_name", "full_name_unicode", "family_name", "given_name":
				// Map family_name/given_name to full_name_unicode for JP MNC
				if !containsElement(elements, document.JpFullName) {
					elements = append(elements, document.JpFullName)
				}
			case "birth_date_unicode", "birth_date":
				elements = append(elements, document.JpBirthDateUnicode)
			case "resident_address_unicode":
				elements = append(elements, document.JpResidentAddressUnicode)
			case "sex_unicode":
				elements = append(elements, document.JpSexUnicode)
			case "local_gov_code":
				elements = append(elements, document.JpLocalGovCode)
			case "individual_number":
				elements = append(elements, document.JpIndividualNumber)
			case "portrait", "Portrait":
				elements = append(elements, document.JpPortrait)
			}
		}

	default:
		// Default to mDL
		docType = document.IsoMDL
		namespace = document.ISO1801351
		credName = "mDL-request"

		// Default attributes if none provided
		if len(attributes) == 0 {
			attributes = []string{"family_name", "given_name", "birth_date", "issuing_country"}
		}

		elements = make([]mdoc.ElementIdentifier, 0, len(attributes))
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
			}
		}
	}

	// Always include age verification
	// ageOver20, err := document.AgeOver(20)
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to create age over : %w", err)
	// }
	// elements = append(elements, ageOver20)

	cred, err := document.NewCredential(
		credName,
		docType,
		namespace,
		elements,
		document.WithLimitDisclosure("required"),
		document.WithPurpose("For KYC"),
		document.WithAlgorithms("ES256"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create credential : %w", err)
	}

	credReq := document.CredentialRequirement{
		CredentialType: document.CredentialTypeMDOC,
		Credentials: []document.Credential{
			*cred,
		},
	}
	return &credReq, nil
}

func (s *Server) GetIdentityRequest(w http.ResponseWriter, r *http.Request) {
	req := GetRequest{}
	if err := parseJSON(r, &req); err != nil {
		jsonErrorResponse(w, fmt.Errorf("failed to parse request: %v", err), http.StatusBadRequest)
		return
	}

	// Get docType from parameters (default to mDL)
	docType := "org.iso.18013.5.1.mDL"
	if req.Parameters != nil {
		if dt, ok := req.Parameters["doc_type"].(string); ok && dt != "" {
			docType = dt
		}
	}

	credReq, err := CredentialRequirement(req.Attributes, docType)
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
	// For org-iso-mdoc, we need to pass the origin for encryptionInfo
	// Use clientDomain as the origin (will be formatted as "https://domain")
	origin := fmt.Sprintf("https://%s", s.clientDomain)
	idReq := createIDReq(req, session, origin, s.sigKey, s.certChain)

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
		doc, err := getVerifiedDoc(devResp, cred.DocType, sessTrans, req.Protocol, s.certManager.GetCertPool())
		if err != nil {
			errMsg := fmt.Sprintf("failed to get doc: %s: %v", cred.DocType, err)
			jsonErrorResponse(w, fmt.Errorf(errMsg), http.StatusBadRequest)
			return
		}

		// Log all available elements in the document for debugging
		log.Printf("Available namespaces and elements in document:")
		for _, ns := range doc.IssuerSigned.GetNameSpaces() {
			log.Printf("  Namespace: %s", ns)
			items, err := doc.IssuerSigned.GetIssuerSignedItems(ns)
			if err != nil {
				log.Printf("    Error getting items: %v", err)
				continue
			}
			for _, item := range items {
				log.Printf("    - %s", item.ElementIdentifier)
			}
		}

		for _, elemName := range cred.ElementIdentifier {
			elemValue, err := doc.GetElementValue(cred.Namespace, elemName)
			if err != nil {
				// Log warning but don't fail - element might not be in the response
				log.Printf("Warning: element not found: %s in namespace %s: %v", elemName, cred.Namespace, err)
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

func containsElement(elements []mdoc.ElementIdentifier, elem mdoc.ElementIdentifier) bool {
	for _, e := range elements {
		if e == elem {
			return true
		}
	}
	return false
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
