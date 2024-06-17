package server

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"

	"github.com/davecgh/go-spew/spew"
)

var (
	roots *x509.CertPool
)

const (
	// Fixed for debugging
	nonce      = "AS59uzWiXXXM5KkCBoO_q_syN1yXfrRABJ6Jtik3fas="
	privateKey = "XF8RGrj4bNixklczV7inHRLxgq34Q5NJm7_kkqdt9oQ="
	publicKey  = "BMyxKlbxQ1R0otFQ-w3jM-P3wMrUMS8jpB_eFwRLYW4QQUq6iur-BdUUVh3QhPrMGU3UZXbWTVnL-1gJ3A07OUw="
)

func init() {
	var err error
	roots, err = GetRootCertificates("./internal/server/pems")
	if err != nil {
		panic("failed to load rootCerts: " + err.Error())
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
	NameSpace  NameSpace             `json:"namespace"`
	Identifier DataElementIdentifier `json:"identifier"`
	Value      DataElementValue      `json:"value"`
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
		idReq = &IdentityRequestPreview{
			Selector: Selector{
				Format:    []string{"mdoc"},
				Retention: Retention{Days: 90},
				DocType:   "org.iso.18013.5.1.mDL",
				Fields: []Field{
					FamilyNameField,
					GivenNameField,
					DocumentNumberField,
				},
			},
			Nonce:           nonce,
			ReaderPublicKey: publicKey,
		}
	case "openid4vp":
		idReq = &IdentityRequestOpenID4VP{
			ClientID:       "digital-credentials.dev",
			ClientIDScheme: "web-origin",
			ResponseType:   "vp_token",
			Nonce:          nonce,
			PresentationDefinition: PresentationDefinition{
				ID: "mDL-request-demo",
				InputDescriptors: []InputDescriptor{
					{
						ID: "org.iso.18013.5.1.mDL",
						Format: Format{
							MsoMdoc: MsoMdoc{
								Alg: []string{"ES256"},
							},
						},
						Constraints: Constraints{
							LimitDisclosure: "required",
							Fields: []PathField{
								FamilyNameField.PathField(),
								GivenNameField.PathField(),
								AgeOver21Field.PathField(),
							},
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

	var devResp *DeviceResponse
	var err error

	switch req.Protocol {
	case "openid4vp":
		devResp, err = ParseOpenID4VP(req.Data)
	case "preview":
		devResp, err = ParsePreview(req.Data, req.Origin)
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
