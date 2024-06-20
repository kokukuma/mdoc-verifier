package server

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"sync"

	"github.com/davecgh/go-spew/spew"
	ep "github.com/kokukuma/identity-credential-api-demo/internal/exchange_protocol"
	"github.com/kokukuma/identity-credential-api-demo/internal/mdoc"
)

var (
	roots *x509.CertPool
	b64   = base64.URLEncoding.WithPadding(base64.StdPadding)

	merchantID = "merchantID"
	teamID     = "teamID"
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
	return &Server{
		sessions: NewSessions(),
	}
}

type Server struct {
	mu       sync.RWMutex
	sessions *Sessions
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
	Elements []Element `json:"elements"`
}

type Element struct {
	NameSpace  mdoc.NameSpace             `json:"namespace"`
	Identifier mdoc.DataElementIdentifier `json:"identifier"`
	Value      mdoc.DataElementValue      `json:"value"`
}

func (s *Server) GetIdentityRequest(w http.ResponseWriter, r *http.Request) {
	req := GetRequest{}
	if err := parseJSON(r, &req); err != nil {
		jsonResponse(w, fmt.Errorf("failed to parse request: %v", err), http.StatusBadRequest)
		return
	}
	spew.Dump(req)

	var idReq interface{}
	var sessionData *ep.SessionData
	var err error

	switch req.Protocol {
	case "preview":
		idReq, sessionData, err = ep.BeginIdentityRequest("preview",
			ep.WithFormat([]string{"mdoc"}),
			ep.WithDocType("org.iso.18013.5.1.mDL"),
			ep.AddField(ep.FamilyNameField),
			ep.AddField(ep.GivenNameField),
			ep.AddField(ep.DocumentNumberField),
		)
		if err != nil {
			jsonResponse(w, fmt.Errorf("failed to parse request: %v", err), http.StatusBadRequest)
			return
		}
	case "openid4vp":
		// TODO: optinoal function for openid4vp
		idReq, sessionData, err = ep.BeginIdentityRequest("openid4vp")
		if err != nil {
			jsonResponse(w, fmt.Errorf("failed to parse request: %v", err), http.StatusBadRequest)
			return
		}
	}

	id, err := s.sessions.SaveIdentitySession(sessionData)
	if err != nil {
		jsonResponse(w, fmt.Errorf("failed to parse request: %v", err), http.StatusBadRequest)
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
		jsonResponse(w, fmt.Errorf("must supply a valid username i.e. foo@bar.com"), http.StatusBadRequest)
		return
	}

	session, err := s.sessions.GetIdentitySession(req.SessionID)
	if err != nil {
		jsonResponse(w, fmt.Errorf("failed to get session"), http.StatusBadRequest)
		return
	}

	var devResp *mdoc.DeviceResponse

	// TODO: exchange_protocolは、package分ける。

	switch req.Protocol {
	case "openid4vp":
		devResp, err = ep.ParseOpenID4VP(req.Data)
	case "preview":
		devResp, err = ep.ParsePreview(req.Data, req.Origin, session.GetPrivateKey(), session.GetNonceByte())
	case "apple":
		devResp, err = ep.ParseApple([]byte(req.Data), merchantID, teamID, session.GetPrivateKey(), session.GetNonceByte())
	}
	if err != nil {
		jsonResponse(w, fmt.Errorf("failed to parse data as JSON"), http.StatusBadRequest)
		return
	}
	spew.Dump(devResp)

	spew.Dump(roots)

	var resp VerifyResponse
	for _, doc := range devResp.Documents {
		if err := doc.IssuerSigned.VerifyIssuerAuth(roots, true); err != nil {
			spew.Dump(err)
			jsonResponse(w, fmt.Errorf("failed to verify issuerAuth: %v", err), http.StatusBadRequest)
			return
		}

		itemsmap, err := doc.IssuerSigned.VerifiedElements()
		if err != nil {
			spew.Dump(err)
			fmt.Println("VerifiedElements:", err)
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
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(c)
	fmt.Fprintf(w, "%s", dj)
}
