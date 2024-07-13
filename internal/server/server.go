package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/dgrijalva/jwt-go"
	"github.com/kokukuma/identity-credential-api-demo/apple_hpke"
	"github.com/kokukuma/identity-credential-api-demo/mdoc"
	"github.com/kokukuma/identity-credential-api-demo/openid4vp"
	"github.com/kokukuma/identity-credential-api-demo/preview_hpke"
	"github.com/kokukuma/identity-credential-api-demo/protocol"
	"gopkg.in/square/go-jose.v2"
)

var (
	roots *x509.CertPool
	b64   = base64.URLEncoding.WithPadding(base64.StdPadding)

	merchantID          = "PassKit_Identity_Test_Merchant_ID"
	teamID              = "PassKit_Identity_Test_Team_ID"
	applePrivateKeyPath = os.Getenv("APPLE_MERCHANT_ENCRYPTION_PRIVATE_KEY_PATH")
)

func NewServer() *Server {
	dir, err := filepath.Abs(filepath.Dir("."))
	if err != nil {
		panic("failed to load rootCerts: " + err.Error())
	}
	roots, err = mdoc.GetRootCertificates(filepath.Join(dir, "internal", "server", "pems"))
	if err != nil {
		panic("failed to load rootCerts: " + err.Error())
	}

	privKey, pubKey, x5c, err := initKeys()
	return &Server{
		sessions:   NewSessions(),
		privateKey: privKey,
		publicKey:  pubKey,
		x5c:        x5c,
	}
}

type Server struct {
	mu         sync.RWMutex
	sessions   *Sessions
	privateKey *ecdsa.PrivateKey
	publicKey  *ecdsa.PublicKey
	certPEM    []byte
	x5c        []string
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
	NameSpace  mdoc.NameSpace             `json:"namespace"`
	Identifier mdoc.DataElementIdentifier `json:"identifier"`
	Value      mdoc.DataElementValue      `json:"value"`
}

type Claims struct {
	openid4vp.IdentityRequestOpenID4VP
	jwt.StandardClaims
}

func (s *Server) RequestJWT(w http.ResponseWriter, r *http.Request) {
	vpReq := openid4vp.IdentityRequestOpenID4VP{
		ClientID:       "fido-kokukuma.jp.ngrok.io",
		ClientIDScheme: "x509_san_dns",

		// ClientID:       "https://fido-kokukuma.jp.ngrok.io/wallet/direct_post",
		// ClientIDScheme: "redirect_uri",

		// ClientID:       "fido-kokukuma.jp.ngrok.io",
		// ClientIDScheme: "pre-registered",

		ResponseType: "vp_token",
		Nonce:        "58812171-3c12-4217-92cc-2aecb40aee0d",
		PresentationDefinition: openid4vp.PresentationDefinition{
			ID: "mDL-request-demo",
			InputDescriptors: []openid4vp.InputDescriptor{
				{
					ID: "eu.europa.ec.eudi.pid.1",
					Format: openid4vp.Format{
						MsoMdoc: openid4vp.MsoMdoc{
							Alg: []string{"ES256"},
						},
					},
					Constraints: openid4vp.Constraints{
						LimitDisclosure: "required",
						Fields: openid4vp.ConvPathField(
							mdoc.EUFamilyName,
						),
					},
				},
			},
		},
		ResponseURI:  "https://fido-kokukuma.jp.ngrok.io/wallet/direct_post",
		ResponseMode: "direct_post.jwt",
		State:        "WVWUJa8X7xZM-r0ODSsBK9MoxSRBtHxR_-4WzGQL-x3xOHFYIosA1a8Ircz8_iO-2jePpuICEcbCSuVPK4KmKA",
		ClientMetadata: openid4vp.ClientMetadata{
			AuthorizationEncryptedResopnseAlg: "ECDH-ES",
			AuthorizationEncryptedResopnseEnc: "A128CBC-HS256",
			IDTokenEncryptedResponseAlg:       "RSA-OAEP-256",
			IDTokenEncryptedResponseEnc:       "A128CBC-HS256",
			JwksURI:                           "https://fido-kokukuma.jp.ngrok.io/wallet/jwks.json",
			SubjectSyntaxTypesSupported:       []string{"urn:ietf:params:oauth:jwk-thumbprint"},
			IDTokenSignedResponseAlg:          "RS256",
		},
	}

	//expirationTime := time.Now().Add(5 * time.Minute)

	token := jwt.NewWithClaims(jwt.SigningMethodES256, Claims{
		IdentityRequestOpenID4VP: vpReq,
		StandardClaims: jwt.StandardClaims{
			IssuedAt: time.Now().Unix(),
			Audience: "https://self-issued.me/v2",
		},
	})
	token.Header["x5c"] = s.x5c
	token.Header["typ"] = "oauth-authz-req+jwt"
	token.Header["kid"] = generateKID(s.publicKey)

	tokenString, err := token.SignedString(s.privateKey)
	if err != nil {
		jsonErrorResponse(w, fmt.Errorf("failed to parse request: %v", err), http.StatusBadRequest)
		return
	}

	spew.Dump("-------------- RequestJWT")
	spew.Dump(tokenString)

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/oauth-authz-req+jwt")

	fmt.Fprintf(w, "%s", tokenString)
}

func generateKID(pubKey *ecdsa.PublicKey) string {
	xBytes := pubKey.X.Bytes()
	yBytes := pubKey.Y.Bytes()
	combined := append(xBytes, yBytes...)
	hash := sha256.Sum256(combined)
	return hex.EncodeToString(hash[:])
}

func generateKIDSha1(pub *ecdsa.PublicKey) []byte {
	b := elliptic.Marshal(pub.Curve, pub.X, pub.Y)
	hash := sha1.Sum(b)
	return hash[:]
}

// func (s *Server) PublicKeys(w http.ResponseWriter, r *http.Request) {
// 	spew.Dump("-------------- PublicKeys")
// 	jwks := map[string]interface{}{
// 		"keys": []map[string]interface{}{
// 			{
// 				"kty": "EC",
// 				"crv": "P-256",
// 				"x":   base64.RawURLEncoding.EncodeToString(s.publicKey.X.Bytes()),
// 				"y":   base64.RawURLEncoding.EncodeToString(s.publicKey.Y.Bytes()),
// 				"use": "sig",
// 				"kid": generateKID(s.publicKey),
// 				"alg": "ES256",
// 				"x5c": s.x5c,
// 			},
// 		},
// 	}
// 	w.Header().Set("Content-Type", "application/json")
// 	json.NewEncoder(w).Encode(jwks)
// }

func (s *Server) JWKS(w http.ResponseWriter, r *http.Request) {
	spew.Dump("-------------- JWKS")
	jwks := map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "EC",
				"crv": "P-256",
				"x":   base64.RawURLEncoding.EncodeToString(s.publicKey.X.Bytes()),
				"y":   base64.RawURLEncoding.EncodeToString(s.publicKey.Y.Bytes()),
				"alg": "ECDH-ES",
				"use": "enc",
				"kid": generateKID(s.publicKey),
			},
		},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jwks)
}

func extractResponseAndState(r *http.Request) (response, state string, err error) {
	// リクエストボディを読み取る
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return "", "", fmt.Errorf("failed to read request body: %v", err)
	}
	defer r.Body.Close()

	// Content-Typeをチェック
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/x-www-form-urlencoded" {
		return "", "", fmt.Errorf("unexpected Content-Type: %s", contentType)
	}

	// ボディをパースする
	values, err := url.ParseQuery(string(body))
	if err != nil {
		return "", "", fmt.Errorf("failed to parse query: %v", err)
	}

	// responseパラメータを取得
	response = values.Get("response")
	if response == "" {
		return "", "", fmt.Errorf("response parameter is missing")
	}

	// stateパラメータを取得
	state = values.Get("state")
	if state == "" {
		return "", "", fmt.Errorf("state parameter is missing")
	}

	return response, state, nil
}

func (s *Server) DirectPost(w http.ResponseWriter, r *http.Request) {
	response, state, err := extractResponseAndState(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	fmt.Println("response: ", response)
	fmt.Println("state: ", state)

	jwe, err := jose.ParseEncrypted(response)
	if err != nil {
		fmt.Printf("Failed to parse JWE: %v\n", err)
		return
	}

	// JWEの復号
	decrypted, err := jwe.Decrypt(s.privateKey)
	if err != nil {
		fmt.Printf("Failed to decrypt JWE: %v\n", err)
		return
	}
	fmt.Println(string(decrypted))

	devResp, sessTrans, err := openid4vp.ParseDeviceResponse(string(decrypted), "origin", "digital-credentials.dev", []byte("58812171-3c12-4217-92cc-2aecb40aee0d"))
	if err != nil {
		spew.Dump(err)
	}
	spew.Dump(devResp)
	spew.Dump(sessTrans)
	skipVerification := true

	var resp VerifyResponse
	for _, doc := range devResp.Documents {
		if !skipVerification {
			if err := mdoc.Verify(doc, sessTrans, roots, true); err != nil {
				spew.Dump(err)
				jsonErrorResponse(w, fmt.Errorf("failed to verify mdoc: %v", err), http.StatusBadRequest)
				return
			}
		}

		itemsmap, err := doc.IssuerSigned.IssuerSignedItems()
		if err != nil {
			spew.Dump(err)
			jsonErrorResponse(w, fmt.Errorf("failed to get IssuerSignedItems: %v", err), http.StatusBadRequest)
			return
		}

		for ns, items := range itemsmap {
			for _, item := range items {
				resp.Elements = append(resp.Elements, Element{
					NameSpace:  ns,
					Identifier: item.ElementIdentifier,
					Value:      item.ElementValue,
				})
			}
		}
	}
	spew.Dump(resp)
}

func (s *Server) GetIdentityRequest(w http.ResponseWriter, r *http.Request) {
	req := GetRequest{}
	if err := parseJSON(r, &req); err != nil {

		jsonErrorResponse(w, fmt.Errorf("failed to parse request: %v", err), http.StatusBadRequest)
		return
	}
	spew.Dump(req)

	var idReq interface{}
	var sessionData *protocol.SessionData
	var err error

	switch req.Protocol {
	case "preview":
		ageOver21, _ := mdoc.AgeOver(21) // only 21 works now...why..
		spew.Dump(ageOver21)
		idReq, sessionData, err = preview_hpke.BeginIdentityRequest(
			preview_hpke.WithFormat([]string{"mdoc"}),
			preview_hpke.WithDocType("org.iso.18013.5.1.mDL"),
			preview_hpke.AddField(mdoc.FamilyName),
			preview_hpke.AddField(mdoc.GivenName),
			preview_hpke.AddField(mdoc.DocumentNumber),
			preview_hpke.AddField(mdoc.BirthDate),
			preview_hpke.AddField(mdoc.IssueDate),
			preview_hpke.AddField(mdoc.IssuingCountry),
			preview_hpke.AddField(ageOver21),
		)
		if err != nil {
			jsonErrorResponse(w, fmt.Errorf("failed to get BeginIdentityRequest: preview: %v", err), http.StatusBadRequest)
			return
		}
	case "openid4vp":
		// TODO: optinoal function for openid4vp
		idReq, sessionData, err = openid4vp.BeginIdentityRequest("digital-credentials.dev")
		if err != nil {
			jsonErrorResponse(w, fmt.Errorf("failed to get BeginIdentityRequest: openid4vp: %v", err), http.StatusBadRequest)
			return
		}
	case "apple":
		idReq, sessionData, err = apple_hpke.BeginIdentityRequest(applePrivateKeyPath)
		if err != nil {
			jsonErrorResponse(w, fmt.Errorf("failed to get BeginIdentityRequest: apple: %v", err), http.StatusBadRequest)
			return
		}
	}

	id, err := s.sessions.SaveIdentitySession(sessionData)
	if err != nil {
		jsonErrorResponse(w, fmt.Errorf("failed to SaveIdentitySession: %v", err), http.StatusBadRequest)
		return
	}

	spew.Dump(idReq)
	spew.Dump(sessionData)

	jsonResponse(w, GetResponse{
		SessionID: id,
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

	session, err := s.sessions.GetIdentitySession(req.SessionID)
	if err != nil {
		jsonErrorResponse(w, fmt.Errorf("failed to GetIdentitySession: %v", err), http.StatusBadRequest)
		return
	}

	var devResp *mdoc.DeviceResponse
	var sessTrans []byte
	var skipVerification bool

	switch req.Protocol {
	case "openid4vp":
		devResp, sessTrans, err = openid4vp.ParseDeviceResponse(req.Data, req.Origin, "digital-credentials.dev", session.GetNonceByte())
	case "preview":
		devResp, sessTrans, err = preview_hpke.ParseDeviceResponse(req.Data, req.Origin, session.GetPrivateKey(), session.GetNonceByte())
	case "apple":
		// Appleのシミュレータが返す値が不完全で検証できないので一旦スキップ
		// * devieSignature不完全な状態で返してくる。
		// * issureAuthのheaderも入ってない
		skipVerification = true
		devResp, sessTrans, err = apple_hpke.ParseDeviceResponse(req.Data, merchantID, teamID, session.GetPrivateKey(), session.GetNonceByte())
	}
	if err != nil {
		jsonErrorResponse(w, fmt.Errorf("failed to ParseDeviceResponse: %v", err), http.StatusBadRequest)
		return
	}
	spew.Dump(devResp)
	spew.Dump(sessTrans)

	var resp VerifyResponse
	for _, doc := range devResp.Documents {
		if !skipVerification {
			if err := mdoc.Verify(doc, sessTrans, roots, true); err != nil {
				spew.Dump(err)
				jsonErrorResponse(w, fmt.Errorf("failed to verify mdoc: %v", err), http.StatusBadRequest)
				return
			}
		}

		itemsmap, err := doc.IssuerSigned.IssuerSignedItems()
		if err != nil {
			spew.Dump(err)
			jsonErrorResponse(w, fmt.Errorf("failed to get IssuerSignedItems: %v", err), http.StatusBadRequest)
			return
		}

		for ns, items := range itemsmap {
			for _, item := range items {
				resp.Elements = append(resp.Elements, Element{
					NameSpace:  ns,
					Identifier: item.ElementIdentifier,
					Value:      item.ElementValue,
				})
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
