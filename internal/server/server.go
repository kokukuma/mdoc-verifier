package server

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"

	"github.com/davecgh/go-spew/spew"
	ep "github.com/kokukuma/identity-credential-api-demo/internal/exchange_protocol"
	"github.com/kokukuma/identity-credential-api-demo/internal/mdoc"
)

var (
	roots *x509.CertPool
	b64   = base64.URLEncoding.WithPadding(base64.StdPadding)

	privateKeyByte, publicKeyByte, nonceByte []byte
)

const (
	// Fixed for debugging
	nonce      = "AS59uzWiXXXM5KkCBoO_q_syN1yXfrRABJ6Jtik3fas="
	privateKey = "XF8RGrj4bNixklczV7inHRLxgq34Q5NJm7_kkqdt9oQ="
	publicKey  = "BMyxKlbxQ1R0otFQ-w3jM-P3wMrUMS8jpB_eFwRLYW4QQUq6iur-BdUUVh3QhPrMGU3UZXbWTVnL-1gJ3A07OUw="
)

func init() {
	var err error
	roots, err = mdoc.GetRootCertificates("./internal/server/pems")
	if err != nil {
		panic("failed to load rootCerts: " + err.Error())
	}

	privateKeyByte, err = b64.DecodeString(privateKey)
	if err != nil {
		panic("failed to decode privateKey: " + err.Error())
	}

	publicKeyByte, err = b64.DecodeString(publicKey)
	if err != nil {
		panic("failed to decode publicKey: " + err.Error())
	}

	nonceByte, err = b64.DecodeString(nonce)
	if err != nil {
		panic("failed to decode nonce: " + err.Error())
	}
}

func NewServer() *Server {
	return &Server{}
}

type Server struct {
	mu sync.RWMutex
}

type GetRequest struct {
	Protocol string `json:"protocol"`
}

type VerifyRequest struct {
	Protocol string `json:"protocol"`
	Data     string `json:"data"`
	Origin   string `json:"origin"`
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

	switch req.Protocol {
	case "preview":
		idReq = &ep.IdentityRequestPreview{
			Selector: ep.Selector{
				Format:    []string{"mdoc"},
				Retention: ep.Retention{Days: 90},
				DocType:   "org.iso.18013.5.1.mDL",
				Fields: []ep.Field{
					ep.FamilyNameField,
					ep.GivenNameField,
					ep.DocumentNumberField,
				},
			},
			Nonce:           nonce,
			ReaderPublicKey: publicKey,
		}
	case "openid4vp":
		idReq = &ep.IdentityRequestOpenID4VP{
			ClientID:       "digital-credentials.dev",
			ClientIDScheme: "web-origin",
			ResponseType:   "vp_token",
			Nonce:          nonce,
			PresentationDefinition: ep.PresentationDefinition{
				ID: "mDL-request-demo",
				InputDescriptors: []ep.InputDescriptor{
					{
						ID: "org.iso.18013.5.1.mDL",
						Format: ep.Format{
							MsoMdoc: ep.MsoMdoc{
								Alg: []string{"ES256"},
							},
						},
						Constraints: ep.Constraints{
							LimitDisclosure: "required",
							Fields: ep.ConvPathField(
								ep.FamilyNameField,
								ep.GivenNameField,
								ep.AgeOver21Field,
							),
						},
					},
				},
			},
		}
	}

	jsonResponse(w, idReq, http.StatusOK)

	return
}

func (s *Server) VerifyIdentityResponse(w http.ResponseWriter, r *http.Request) {
	req := VerifyRequest{}
	if err := parseJSON(r, &req); err != nil {
		jsonResponse(w, fmt.Errorf("must supply a valid username i.e. foo@bar.com"), http.StatusBadRequest)
		return
	}
	spew.Dump(req)

	var devResp *mdoc.DeviceResponse
	var err error

	switch req.Protocol {
	case "openid4vp":
		devResp, err = ep.ParseOpenID4VP(req.Data)
	case "preview":
		devResp, err = ep.ParsePreview(req.Data, req.Origin, privateKeyByte, publicKeyByte, nonceByte)
	case "apple":
		devResp, err = ep.ParseApple(req.Data, "merchantID", "temaID", privateKeyByte, publicKeyByte, nonceByte)
	}
	if err != nil {
		jsonResponse(w, fmt.Errorf("failed to parse data as JSON"), http.StatusBadRequest)
		return
	}
	spew.Dump(devResp)

	var resp VerifyResponse
	for _, doc := range devResp.Documents {
		if err := doc.IssuerSigned.VerifyIssuerAuth(roots); err != nil {
			jsonResponse(w, fmt.Errorf("failed to verify issuerAuth: %v", err), http.StatusBadRequest)
			return
		}

		itemsmap, err := doc.IssuerSigned.VerifiedElements()
		if err != nil {
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
