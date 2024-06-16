package server

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"sync"

	"github.com/davecgh/go-spew/spew"
	"github.com/kouzoh/kokukuma-fido/internal/model"
)

var (
	// decoded, err := base64.RawURLEncoding.DecodeString(msg.Token)
	b64 = base64.StdEncoding.WithPadding(base64.StdPadding)
	// b64 = base64.RawURLEncoding.WithPadding(base64.NoPadding)
	//b64 = base64.URLEncoding.WithPadding(base64.NoPadding)

	roots = x509.NewCertPool()
)

const (
	nonce      = "AS59uzWiXXXM5KkCBoO_q_syN1yXfrRABJ6Jtik3fas="
	privateKey = "XF8RGrj4bNixklczV7inHRLxgq34Q5NJm7_kkqdt9oQ="
	publicKey  = "BMyxKlbxQ1R0otFQ-w3jM-P3wMrUMS8jpB_eFwRLYW4QQUq6iur-BdUUVh3QhPrMGU3UZXbWTVnL-1gJ3A07OUw="
)

func init() {
	pems, err := loadCertificatesFromDirectory("./internal/server/pems")
	if err != nil {
		panic("failed to load rootCerts: " + err.Error())
	}

	for name, pem := range pems {
		if ok := roots.AppendCertsFromPEM(pem); !ok {
			fmt.Println("failed to load pem: " + name)
		}
	}
}

func loadCertificatesFromDirectory(dirPath string) (map[string][]byte, error) {
	pems := map[string][]byte{}

	// Read files in directory
	files, err := ioutil.ReadDir(dirPath)
	if err != nil {
		return nil, err
	}

	// Iterate over files
	for _, file := range files {
		if file.IsDir() {
			continue // skip directories
		}
		if strings.HasSuffix(file.Name(), ".pem") {
			filePath := filepath.Join(dirPath, file.Name())
			data, err := ioutil.ReadFile(filePath)
			if err != nil {
				log.Printf("Failed to read file: %s, err: %v", filePath, err)
				continue // continue with other files even if one fails
			}
			pems[file.Name()] = data
		}
	}
	return pems, nil
}

func NewServer() *Server {
	return &Server{}
}

type Server struct {
	mu       sync.RWMutex
	users    *model.Users
	sessions *model.Sessions
}

type GetRequest struct {
	Protocol string `json:"protocol"`
}

type VerifyRequest struct {
	Protocol string `json:"protocol"`
	Data     string `json:"data"`
	Origin   string `json:"origin"`
}

type VerifyResponse struct{}

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

func (s *Server) GetIdentityRequest(w http.ResponseWriter, r *http.Request) {
	req := GetRequest{}
	if err := parseJSON(r, &req); err != nil {
		spew.Dump(err)
		jsonResponse(w, fmt.Errorf("must supply a valid username i.e. foo@bar.com"), http.StatusBadRequest)
		return
	}

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

func (s *Server) VerifyResponse(w http.ResponseWriter, r *http.Request) {
	resp := VerifyRequest{}
	if err := parseJSON(r, &resp); err != nil {
		jsonResponse(w, fmt.Errorf("must supply a valid username i.e. foo@bar.com"), http.StatusBadRequest)
		return
	}
	spew.Dump(resp)

	var devResp *DeviceResponse
	var err error

	switch resp.Protocol {
	case "openid4vp":
		devResp, err = ParseOpenID4VP(resp.Data)
	case "preview":
		devResp, err = ParsePreview(resp.Data, resp.Origin)
	}
	if err != nil {
		jsonResponse(w, fmt.Errorf("failed to parse data as JSON"), http.StatusBadRequest)
		return
	}
	spew.Dump(devResp)

	for _, doc := range devResp.Documents {
		if err := doc.IssuerSigned.VerifyIssuerAuth(roots); err != nil {
			jsonResponse(w, fmt.Errorf("failed to verify issuerAuth: %v", err), http.StatusBadRequest)
			return
		}

		items, err := doc.IssuerSigned.VerifiedElements()
		if err != nil {
			fmt.Println("VerifiedElements:", err)
			return
		}
		spew.Dump(items)
	}

	jsonResponse(w, VerifyResponse{}, http.StatusOK)
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

// DecodeBase64URL decodes a Base64URL encoded string, adding padding if necessary
func DecodeBase64URL(encoded string) ([]byte, error) {
	// Add padding if necessary
	padding := len(encoded) % 4
	if padding > 0 {
		encoded += string(make([]byte, 4-padding))
		for i := 0; i < 4-padding; i++ {
			encoded += "="
		}
	}

	// Decode the Base64URL string
	return base64.URLEncoding.DecodeString(encoded)
}
