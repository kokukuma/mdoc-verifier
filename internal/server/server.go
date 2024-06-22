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
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/kokukuma/identity-credential-api-demo/internal/apple_hpke"
	"github.com/kokukuma/identity-credential-api-demo/internal/mdoc"
	"github.com/kokukuma/identity-credential-api-demo/internal/openid4vp"
	"github.com/kokukuma/identity-credential-api-demo/internal/preview_hpke"
	"github.com/kokukuma/identity-credential-api-demo/internal/protocol"
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
	var sessionData *protocol.SessionData
	var err error

	switch req.Protocol {
	case "preview":
		idReq, sessionData, err = preview_hpke.BeginIdentityRequest(
			preview_hpke.WithFormat([]string{"mdoc"}),
			preview_hpke.WithDocType("org.iso.18013.5.1.mDL"),
			preview_hpke.AddField(mdoc.FamilyName),
			preview_hpke.AddField(mdoc.GivenName),
			preview_hpke.AddField(mdoc.DocumentNumber),
			preview_hpke.AddField(mdoc.BirthDate),
			preview_hpke.AddField(mdoc.IssueDate),
		)
		if err != nil {
			jsonResponse(w, fmt.Errorf("failed to parse request: %v", err), http.StatusBadRequest)
			return
		}
	case "openid4vp":
		// TODO: optinoal function for openid4vp
		idReq, sessionData, err = openid4vp.BeginIdentityRequest()
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
	var sessTrans []byte

	switch req.Protocol {
	case "openid4vp":
		devResp, sessTrans, err = openid4vp.ParseDeviceResponse(req.Data)
	case "preview":
		devResp, sessTrans, err = preview_hpke.ParseDeviceResponse(req.Data, req.Origin, session.GetPrivateKey(), session.GetNonceByte())
	case "apple":
		devResp, sessTrans, err = apple_hpke.ParseDeviceResponse([]byte(req.Data), merchantID, teamID, session.GetPrivateKey(), session.GetNonceByte())
	}
	if err != nil {
		jsonResponse(w, fmt.Errorf("failed to parse data as JSON"), http.StatusBadRequest)
		return
	}
	spew.Dump(devResp)

	var resp VerifyResponse
	for _, doc := range devResp.Documents {
		spew.Dump(doc)
		mso, err := doc.IssuerSigned.GetMobileSecurityObject(time.Now())
		if err != nil {
			spew.Dump(err)
			jsonResponse(w, fmt.Errorf("failed to get mso: %s", err), http.StatusBadRequest)
			return
		}

		spew.Dump(mso)

		if err := mdoc.VerifyDeviceSigned(mso, doc, sessTrans); err != nil {
			spew.Dump("1", err)
			jsonResponse(w, fmt.Errorf("failed to get mso: %s", err), http.StatusBadRequest)
			return
		}

		if err := mdoc.VerifyIssuerAuth(doc.IssuerSigned.IssuerAuth, roots, true); err != nil {
			spew.Dump("2", err)
			jsonResponse(w, fmt.Errorf("failed to verify issuerAuth: %v", err), http.StatusBadRequest)
			return
		}

		itemsmap, err := mdoc.VerifiedElements(doc.IssuerSigned.NameSpaces, mso)
		if err != nil {
			spew.Dump("3", err)
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
