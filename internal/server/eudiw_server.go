package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/kokukuma/mdoc-verifier/decoder"
	"github.com/kokukuma/mdoc-verifier/decoder/openid4vp"
	"github.com/kokukuma/mdoc-verifier/document"
	"github.com/kokukuma/mdoc-verifier/mdoc"
	"github.com/kokukuma/mdoc-verifier/session_transcript"
	"github.com/skip2/go-qrcode"
)

// CreateEUDIWCredential creates a credential requirement based on selected attributes
func CreateEUDIWCredential(attributes []string) *document.CredentialRequirement {
	// Default attributes if none provided
	if len(attributes) == 0 {
		attributes = []string{"family_name", "given_name", "birth_date", "issuing_country"}
	}

	// Create ISO mdoc elements
	isoElements := make([]mdoc.ElementIdentifier, 0, len(attributes))
	eudiElements := make([]mdoc.ElementIdentifier, 0, len(attributes))

	// Map attribute names to the corresponding element identifiers
	for _, attr := range attributes {
		switch attr {
		case "family_name":
			isoElements = append(isoElements, document.IsoFamilyName)
			eudiElements = append(eudiElements, document.EudiFamilyName)
		case "given_name":
			isoElements = append(isoElements, document.IsoGivenName)
			eudiElements = append(eudiElements, document.EudiGivenName)
		case "birth_date":
			isoElements = append(isoElements, document.IsoBirthDate)
			eudiElements = append(eudiElements, document.EudiBirthDate)
		case "expiry_date":
			isoElements = append(isoElements, document.IsoExpiryDate)
			// Add EUDI equivalent if exists
		case "issuing_country":
			isoElements = append(isoElements, document.IsoIssuingCountry)
			eudiElements = append(eudiElements, document.EudiIssuingCountry)
		case "issuing_authority":
			isoElements = append(isoElements, document.IsoIssuingAuthority)
			// Add EUDI equivalent if exists
		case "document_number":
			isoElements = append(isoElements, document.IsoDocumentNumber)
			// Add EUDI equivalent if exists
		}
	}

	return &document.CredentialRequirement{
		CredentialType: document.CredentialTypeMDOC,
		Credentials: []document.Credential{
			{
				ID:                "mdl",
				DocType:           document.IsoMDL,
				Namespace:         document.ISO1801351,
				ElementIdentifier: isoElements,
				Retention:         90,
				LimitDisclosure:   "required",
			},
			{
				ID:                "eudi-pid",
				DocType:           document.EudiPid,
				Namespace:         document.EUDIPID1,
				ElementIdentifier: eudiElements,
				Retention:         90,
				LimitDisclosure:   "required",
			},
		},
	}
}

func (s *Server) StartIdentityRequest(w http.ResponseWriter, r *http.Request) {
	req := GetRequest{}
	if err := parseJSON(r, &req); err != nil {
		// Continue with empty attributes which will use defaults
	}

	credReq := CreateEUDIWCredential(req.Attributes)
	session, err := s.sessions.NewSession("", credReq)
	if err != nil {
		jsonErrorResponse(w, fmt.Errorf("failed to SaveSession: %v", err), http.StatusBadRequest)
		return
	}

	// TODO: by valueの場合とby referenceの場合両方やってみるか？
	jar := openid4vp.JWTSecuredAuthorizeRequest{
		AuthorizeEndpoint: "openid4vp://verifier-backend.eudiw.dev",
		ClientID:          s.serverDomain,
		RequestURI:        fmt.Sprintf("https://%s/wallet/request.jwt/%s", s.serverDomain, session.ID), // request-id ?
	}

	// Create the URL
	authURL := jar.String()

	// Check if QR code is requested
	wantQRCode := false
	if qrParam := r.URL.Query().Get("qrcode"); qrParam == "true" {
		wantQRCode = true
	} else if r.Method == "POST" {
		if crossDevice, ok := req.Parameters["cross_device"]; ok {
			if b, ok := crossDevice.(bool); ok && b {
				wantQRCode = true
			}
		}
	}

	// Generate QR code if requested
	var qrCodeBase64 string
	if wantQRCode {
		// Generate QR code PNG
		var qrCode []byte
		qrCode, err = qrcode.Encode(authURL, qrcode.Medium, 256)
		if err != nil {
			// If QR code generation fails, we still return the URL but with no QR code
			log.Printf("Failed to generate QR code: %v", err)
		} else {
			// Convert to base64
			qrCodeBase64 = base64.StdEncoding.EncodeToString(qrCode)
		}
	}

	// Return response with optional QR code
	if qrCodeBase64 != "" {
		jsonResponse(w, struct {
			URL       string `json:"url"`
			QRCode    string `json:"qrcode"`
			SessionID string `json:"sessino_id"`
		}{
			URL:       authURL,
			QRCode:    qrCodeBase64,
			SessionID: session.ID,
		}, http.StatusOK)
	} else {
		jsonResponse(w, struct {
			URL string `json:"url"`
		}{
			URL: authURL,
		}, http.StatusOK)
	}
}

func (s *Server) RequestJWT(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sessionID := vars["sessionid"]
	session, err := s.sessions.GetSession(sessionID)
	if err != nil {
		jsonErrorResponse(w, fmt.Errorf("failed to GetSession: %v", err), http.StatusBadRequest)
		return
	}

	// create authorize request
	vpReq := openid4vp.AuthorizationRequest{
		ClientID:       s.serverDomain,
		ClientIDScheme: "x509_san_dns",
		ResponseType:   "vp_token",
		ResponseMode:   "direct_post.jwt",
		ResponseURI:    fmt.Sprintf("https://%s/wallet/direct_post", s.serverDomain),
		Nonce:          session.Nonce.String(),
		State:          sessionID,

		// TODO: presentation_definition_uri, client_metadata_uri使う形も試してみるか？
		//       まぁどっちでもいい。
		PresentationDefinition: session.CredentialRequirement.PresentationDefinition(),
		// TODO: JwksURIは外から渡す形にしたほうがいい
		ClientMetadata: openid4vp.CreateClientMetadata(s.serverDomain),
	}

	// create RequestObject
	ro := openid4vp.RequestObject{
		AuthorizationRequest: vpReq,
		StandardClaims: jwt.StandardClaims{
			IssuedAt: time.Now().Unix(),
			Audience: "https://self-issued.me/v2",
		},
	}
	tokenString, err := ro.Sign(s.sigKey, s.certChain)
	if err != nil {
		jsonErrorResponse(w, fmt.Errorf("failed to parse request: %v", err), http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/oauth-authz-req+jwt")

	fmt.Fprintf(w, "%s", tokenString)
}

func (s *Server) JWKS(w http.ResponseWriter, r *http.Request) {
	jwks, err := ecdsaPublicKeyToJWKS(&s.encKey.PublicKey)
	if err != nil {
		panic(err)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jwks)
}

func (s *Server) DirectPost(w http.ResponseWriter, r *http.Request) {
	ar, err := decoder.ParseDirectPostJWT(r, s.encKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	log.Printf("authorize request = %s", ar)

	session, err := s.sessions.GetSession(ar.State)
	if err != nil {
		jsonErrorResponse(w, fmt.Errorf("failed to GetSession: %v", err), http.StatusBadRequest)
		return
	}

	// 1. get session_transcript
	sessTrans, err := session_transcript.OID4VPHandover([]byte(session.Nonce.String()), s.serverDomain, fmt.Sprintf("https://%s/wallet/direct_post", s.serverDomain), ar.APU)
	if err != nil {
		jsonErrorResponse(w, fmt.Errorf("failed to get sessTrans: %v", err), http.StatusBadRequest)
		return
	}

	// 2. parse mdoc device response
	devResp, err := decoder.AuthzRespOpenID4VP(ar)
	if err != nil {
		jsonErrorResponse(w, fmt.Errorf("failed to parse device responsee: %v", err), http.StatusBadRequest)
		return
	}

	// 3. verify mdoc device response
	var resp VerifyResponse
	for _, cred := range session.CredentialRequirement.Credentials {
		doc, err := devResp.GetDocument(cred.DocType)
		if err != nil {
			errMsg := fmt.Sprintf("document not found: %s: %v", cred.DocType, err)
			jsonErrorResponse(w, fmt.Errorf(errMsg), http.StatusBadRequest)
			return
		}

		if err := mdoc.NewVerifier(
			s.certManager.GetCertPool(),
			mdoc.WithSkipVerifyDeviceSigned(),
			// mdoc.WithSkipSignedDateValidation(),
			// mdoc.WithCertCurrentTime(date),
		).Verify(doc, sessTrans); err != nil {
			jsonErrorResponse(w, fmt.Errorf("failed to verify mdoc: %v", err), http.StatusBadRequest)
			return
		}

		for _, elemName := range cred.ElementIdentifier {
			elemValue, err := doc.GetElementValue(cred.Namespace, elemName)
			if err != nil {
				errMsg := fmt.Sprintf("element not found: %s: %v", elemName, err)
				jsonErrorResponse(w, fmt.Errorf(errMsg), http.StatusBadRequest)
				return
			}
			resp.Elements = append(resp.Elements, Element{
				NameSpace:  cred.Namespace,
				Identifier: elemName,
				Value:      elemValue,
			})
			log.Printf("element name=%s, value=%s", elemName, elemValue)
		}
	}

	s.sessions.AddVerifyResponse(ar.State, resp)

	jsonResponse(w, struct {
		RedirectURI string `json:"redirect_uri"`
	}{
		// TODO: the redirect_uri should be obtained at the start endpoint and save it on session.
		RedirectURI: fmt.Sprintf("https://%s?session_id=%s", s.clientDomain, ar.State),
	}, http.StatusOK)
}

type FinishIdentityRequest struct {
	SessionID string `json:"session_id"`
}

func (s *Server) FinishIdentityRequest(w http.ResponseWriter, r *http.Request) {
	req := FinishIdentityRequest{}
	if err := parseJSON(r, &req); err != nil {
		jsonErrorResponse(w, fmt.Errorf("failed to parse request: %v", err), http.StatusBadRequest)
		return
	}

	resp, err := s.sessions.GetVerifyResponse(req.SessionID) // transaction-id
	if err != nil {
		jsonErrorResponse(w, fmt.Errorf("failed to GetSession: %v", err), http.StatusBadRequest)
		return
	}

	jsonResponse(w, resp, http.StatusOK)
}
