package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/kokukuma/mdoc-verifier/mdoc"
	"github.com/kokukuma/mdoc-verifier/openid4vp"
)

func (s *Server) StartIdentityRequest(w http.ResponseWriter, r *http.Request) {
	nonce, err := CreateNonce()
	if err != nil {
		jsonErrorResponse(w, fmt.Errorf("failed to SaveSession: %v", err), http.StatusBadRequest)
		return
	}

	session := &Session{
		Nonce: nonce,
	}

	id, err := s.sessions.SaveSession(session)
	if err != nil {
		jsonErrorResponse(w, fmt.Errorf("failed to SaveSession: %v", err), http.StatusBadRequest)
		return
	}

	// TODO: by valueの場合とby referenceの場合両方やってみるか？
	jar := openid4vp.JWTSecuredAuthorizeRequest{
		AuthorizeEndpoint: "eudi-openid4vp://verifier-backend.eudiw.dev",
		ClientID:          serverDomain,
		RequestURI:        fmt.Sprintf("https://%s/wallet/request.jwt/%s", serverDomain, id),
	}

	jsonResponse(w, struct {
		URL string `json:"url"`
	}{
		URL: jar.String(),
	}, http.StatusOK)
}

func (s *Server) RequestJWT(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sessionID := vars["sessionid"]
	session, err := s.sessions.GetIdentitySession(sessionID)
	if err != nil {
		jsonErrorResponse(w, fmt.Errorf("failed to GetIdentitySession: %v", err), http.StatusBadRequest)
		return
	}

	// create authorize request
	vpReq := openid4vp.AuthorizationRequest{
		ClientID:       "fido-kokukuma.jp.ngrok.io",
		ClientIDScheme: "x509_san_dns",
		ResponseType:   "vp_token",
		ResponseMode:   "direct_post.jwt",
		ResponseURI:    "https://fido-kokukuma.jp.ngrok.io/wallet/direct_post",
		Nonce:          session.Nonce.String(),
		State:          sessionID,

		// TODO: presentation_definition_uri, client_metadata_uri使う形も試してみるか？
		//       まぁどっちでもいい。
		PresentationDefinition: openid4vp.CreatePresentationDefinition(),
		// TODO: JwksURIは外から渡す形にしたほうがいい
		ClientMetadata: openid4vp.CreateClientMetadata(),
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
	ar, err := openid4vp.ParseDirectPostJWT(r, s.encKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	spew.Dump(ar)

	session, err := s.sessions.GetIdentitySession(ar.State)
	if err != nil {
		jsonErrorResponse(w, fmt.Errorf("failed to GetIdentitySession: %v", err), http.StatusBadRequest)
		return
	}

	devResp, sessTrans, err := openid4vp.ParseDeviceResponse(ar, "https://fido-kokukuma.jp.ngrok.io/wallet/direct_post", serverDomain, []byte(session.Nonce.String()), "eudiw")
	if err != nil {
		spew.Dump(err)
	}

	spew.Dump(devResp)
	spew.Dump(sessTrans)

	skipVerification := false

	var resp VerifyResponse
	for _, doc := range devResp.Documents {
		if !skipVerification {
			if err := mdoc.Verify(doc, sessTrans, roots, true, true); err != nil {
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
	s.sessions.AddVerifyResponse(ar.State, resp)

	jsonResponse(w, struct {
		RedirectURI string `json:"redirect_uri"`
	}{
		RedirectURI: fmt.Sprintf("https://client-kokukuma.jp.ngrok.io?session_id=%s", ar.State),
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

	resp, err := s.sessions.GetVerifyResponse(req.SessionID)
	if err != nil {
		jsonErrorResponse(w, fmt.Errorf("failed to GetIdentitySession: %v", err), http.StatusBadRequest)
		return
	}

	spew.Dump(resp)
	jsonResponse(w, resp, http.StatusOK)
}
