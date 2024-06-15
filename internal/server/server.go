package server

import (
	"crypto/ecdsa"
	"crypto/sha256"
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

	"github.com/cisco/go-hpke"
	"github.com/davecgh/go-spew/spew"
	"github.com/kouzoh/kokukuma-fido/internal/model"
	"github.com/veraison/go-cose"

	"github.com/fxamacker/cbor/v2"
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

type GetResponse struct {
	Nonce      string `json:"nonce"`
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
}

type VerifyRequest struct {
	Protocol string       `json:"protocol"`
	Data     string       `json:"data"`
	Origin   string       `json:"origin"`
	State    *GetResponse `json:"state"`
}

type VerifyResponse struct{}

func ParseRequest(r *http.Request) (*GetRequest, error) {
	var req GetRequest

	if r == nil || r.Body == nil {
		return nil, errors.New("No request given")
	}

	defer r.Body.Close()
	defer io.Copy(io.Discard, r.Body)

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		return nil, err
	}
	return &req, nil
}

func ParseVerifyRequest(r *http.Request) (*VerifyRequest, error) {
	var resp VerifyRequest

	if r == nil || r.Body == nil {
		return nil, errors.New("No request given")
	}

	defer r.Body.Close()
	defer io.Copy(io.Discard, r.Body)

	err := json.NewDecoder(r.Body).Decode(&resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

func (s *Server) GetRequest(w http.ResponseWriter, r *http.Request) {
	req, err := ParseRequest(r)
	if err != nil {
		jsonResponse(w, fmt.Errorf("must supply a valid username i.e. foo@bar.com"), http.StatusBadRequest)
		return
	}
	spew.Dump(req)

	jsonResponse(w, GetResponse{
		Nonce:      nonce,
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}, http.StatusOK)

	return
}

func VerifyOpenID4VP(data string) error {
	var msg OpenID4VPData
	if err := json.Unmarshal([]byte(data), &msg); err != nil {
		return fmt.Errorf("failed to parse data as JSON")
	}
	spew.Dump(msg)

	decoded, err := DecodeBase64URL(msg.VPToken)
	if err != nil {
		return fmt.Errorf("failed to decode base64")
	}
	spew.Dump(decoded)

	var claims DeviceResponse
	if err := cbor.Unmarshal(decoded, &claims); err != nil {
		return fmt.Errorf("failed to parse data as JSON")
	}

	spew.Dump(claims)

	return nil
}

func (s *Server) VerifyResponse(w http.ResponseWriter, r *http.Request) {
	resp, err := ParseVerifyRequest(r)
	if err != nil {
		jsonResponse(w, fmt.Errorf("must supply a valid username i.e. foo@bar.com"), http.StatusBadRequest)
		return
	}
	spew.Dump(resp)

	if resp.Protocol == "openid4vp" {
		if err := VerifyOpenID4VP(resp.Data); err != nil {
			jsonResponse(w, fmt.Errorf("failed to parse data as JSON"), http.StatusBadRequest)
			return
		}
	}

	var msg PreviewData
	if err := json.Unmarshal([]byte(resp.Data), &msg); err != nil {
		jsonResponse(w, fmt.Errorf("failed to parse data as JSON"), http.StatusBadRequest)
		return
	}

	// decoded, err := b64.DecodeString(msg.Token)
	decoded, err := DecodeBase64URL(msg.Token)
	if err != nil {
		log.Fatalf("Error decoding Base64URL string: %v", err)
		jsonResponse(w, fmt.Errorf("failed to decode base64"), http.StatusBadRequest)
		return
	}

	var claims AndroidHPKEV1
	if err := cbor.Unmarshal(decoded, &claims); err != nil {
		log.Fatalf("Error unmarshal cbor string: %v", err)
		jsonResponse(w, fmt.Errorf("failed to parse data as JSON"), http.StatusBadRequest)
		return
	}

	plaintext, err := DecryptAndroidHPKEV1(&claims, privateKey, publicKey, nonce, resp.Origin)
	if err != nil {
		log.Fatalf("Error decryptAndroidHPKEV1: %v", err)
		jsonResponse(w, fmt.Errorf("failed to decript"), http.StatusBadRequest)
		return
	}

	var deviceResp DeviceResponse
	if err := cbor.Unmarshal(plaintext, &deviceResp); err != nil {
		log.Fatalf("Error unmarshal cbor string: %v", err)
		jsonResponse(w, fmt.Errorf("failed to parse data as JSON"), http.StatusBadRequest)
		return
	}
	spew.Dump(deviceResp)

	items := []IssuerSignedItem{}
	for _, doc := range deviceResp.Documents {
		for ns, vals := range doc.IssuerSigned.NameSpaces {
			spew.Dump(ns)
			for _, val := range vals {
				var item IssuerSignedItem
				if err := cbor.Unmarshal(val, &item); err != nil {
					spew.Dump(err)
				}
				// TODO: hashの計算, MSOの値と比較
				// IssuerSignedItemBytesを指定されたハッシュ関数でhash化
				// digestIDで対応するhashを探して比較する
				items = append(items, item)
			}
		}
		spew.Dump("------------- doc.IssuerSigned.IssuerAuth")
		spew.Dump(doc.IssuerSigned.IssuerAuth.Payload)

		var topLevelData interface{}
		err := cbor.Unmarshal(doc.IssuerSigned.IssuerAuth.Payload, &topLevelData)
		if err != nil {
			fmt.Println("Error unmarshalling top level CBOR:", err)
			return
		}

		var mso MobileSecurityObject
		if err := cbor.Unmarshal(topLevelData.(cbor.Tag).Content.([]byte), &mso); err != nil {
			log.Fatalf("Error unmarshal cbor string: %v", err)
			jsonResponse(w, fmt.Errorf("failed to parse data as JSON"), http.StatusBadRequest)
			return
		}

		alg, err := doc.IssuerSigned.IssuerAuth.Headers.Protected.Algorithm()
		if err != nil {
			log.Fatalf("Error unmarshal cbor string: %v", err)
			jsonResponse(w, fmt.Errorf("failed to parse data as JSON"), http.StatusBadRequest)
			return
		}

		spew.Dump("------------- MobileSecurityObject")
		spew.Dump(mso, alg)
		// spew.Dump(doc.IssuerSigned.IssuerAuth.Headers.Protected)
		// spew.Dump(doc.IssuerSigned.IssuerAuth.Headers.Unprotected)
		rawX5Chain, ok := doc.IssuerSigned.IssuerAuth.Headers.Unprotected[cose.HeaderLabelX5Chain]
		if !ok {
			log.Fatalf("failed to get x5chain")
			jsonResponse(w, fmt.Errorf("failed to parse data as JSON"), http.StatusBadRequest)
			return
		}
		spew.Dump(rawX5Chain)

		rawX5ChainBytes, ok := rawX5Chain.([][]byte)
		if !ok {
			rawX5ChainByte, ok := rawX5Chain.([]byte)
			if !ok {
				log.Fatalf("failed to get x5chain")
				jsonResponse(w, fmt.Errorf("failed to parse data as JSON"), http.StatusBadRequest)
				return
			}
			rawX5ChainBytes = append(rawX5ChainBytes, rawX5ChainByte)
		}

		// Assuming rawX5Chain is a slice of byte slices (each representing a DER encoded certificate)
		certificates, err := parseCertificates(rawX5ChainBytes)
		if err != nil {
			log.Fatalf("Failed to parseCertificates: %v", err)
			jsonResponse(w, fmt.Errorf("failed to parse data as JSON"), http.StatusBadRequest)
			return
		}
		documentSigningKey, ok := certificates[0].PublicKey.(*ecdsa.PublicKey)
		if !ok {
			log.Fatalf("Failed to parseCertificates: %v", err)
			jsonResponse(w, fmt.Errorf("failed to parse data as JSON"), http.StatusBadRequest)
			return
		}

		// spew.Dump("------------- DeviceKey")
		// spew.Dump(mso.DeviceKeyInfo.DeviceKey)
		verifier, err := cose.NewVerifier(alg, documentSigningKey)
		if err != nil {
			log.Fatalf("Failed to create NewVerifier: %v", err)
			jsonResponse(w, fmt.Errorf("failed to parse data as JSON"), http.StatusBadRequest)
			return
		}

		spew.Dump("verify")
		spew.Dump(doc.IssuerSigned.IssuerAuth.Verify(nil, verifier))
		//

	}
	// spew.Dump("------------- items")
	// spew.Dump(items)

	jsonResponse(w, VerifyResponse{}, http.StatusOK)
}

func parseCertificates(rawCerts [][]byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for _, certData := range rawCerts {
		cert, err := x509.ParseCertificate(certData)
		if err != nil {
			return nil, fmt.Errorf("error parsing certificate: %v", err)
		}
		certs = append(certs, cert)
	}

	// TODO: I don't have real mDL: current issuser is self-signed on Device.

	// veirfy
	// opts := x509.VerifyOptions{
	// 	Roots:     roots,
	// 	KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	// }

	// // Perform the verification
	// _, err := certs[0].Verify(opts)
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to verify certificate chain: %v", err)
	// }

	return certs, nil
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

// DecryptAndroidHPKEV1 decrypts the CipherText in the AndroidHPKEV1 struct using the provided recipient private key
func DecryptAndroidHPKEV1(claims *AndroidHPKEV1, recipientPrivKey, recipientPubKey, nonceStr, origin string) ([]byte, error) {
	// Decode base64 encoded recipient private key to byte slice
	//privKey, err := base64.StdEncoding.DecodeString(recipientPrivKey)
	privKey, err := DecodeBase64URL(recipientPrivKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode recipient private key: %v", err)
	}

	pubKey, err := DecodeBase64URL(recipientPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode recipient private key: %v", err)
	}

	nonce, err := DecodeBase64URL(nonceStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode recipient private key: %v", err)
	}

	// Initialize the HPKE context
	suite, err := hpke.AssembleCipherSuite(hpke.DHKEM_P256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AESGCM128)
	if err != nil {
		return nil, fmt.Errorf("error assembling cipher suite: %v", err)
	}

	// Deserialize the recipient's private key
	skR, err := suite.KEM.DeserializePrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("error deserializing private key: %v", err)
	}

	// Decrypt the ciphertext
	aad, err := generateBrowserSessionTranscript(nonce, origin, digest(pubKey))
	if err != nil {
		return nil, fmt.Errorf("failed to create aad: %v", err)
	}

	// Setup the HPKE receiver context using SetupBaseR
	ctxR, err := hpke.SetupBaseR(suite, skR, claims.EncryptionParameters.PKEM, aad)
	if err != nil {
		return nil, fmt.Errorf("error setting up receiver context: %v", err)
	}

	// packageName := "com.android.identity.wallet"
	// packageName := "com.android.mdl.appreader"
	// aad, err := generateAndroidSessionTranscript(nonce, packageName, digest(pubKey))
	// spew.Dump(aad)
	// spew.Dump(claims.CipherText)
	// spew.Dump(base64.URLEncoding.EncodeToString(aad))
	// spew.Dump(base64.URLEncoding.EncodeToString(digest(claims.CipherText)))
	// spew.Dump(base64.URLEncoding.EncodeToString(claims.EncryptionParameters.PKEM))

	plainText, err := ctxR.Open(nil, claims.CipherText) // No associated data
	if err != nil {
		return nil, fmt.Errorf("error decrypting ciphertext: %v", err)
	}

	// Print or process the decrypted plaintext as needed
	fmt.Printf("Decrypted text: %s\n", base64.URLEncoding.EncodeToString(plainText))

	return plainText, nil
}

func digest(message []byte) []byte {
	hasher := sha256.New()
	hasher.Write(message)
	return hasher.Sum(nil)
}

const BROWSER_HANDOVER_V1 = "BrowserHandoverv1"

type OriginInfo struct {
	Cat     int     `json:"cat"`
	Type    int     `json:"type"`
	Details Details `json:"details"`
}

type Details struct {
	BaseURL string `json:"baseUrl"`
}

func generateBrowserSessionTranscript(nonce []byte, origin string, requesterIdHash []byte) ([]byte, error) {
	originInfo := OriginInfo{
		Cat:  1,
		Type: 1,
		Details: Details{
			BaseURL: origin,
		},
	}
	originInfoBytes, err := cbor.Marshal(originInfo)
	if err != nil {
		return nil, fmt.Errorf("error encoding origin info: %v", err)
	}

	// Create the final CBOR array
	browserHandover := []interface{}{
		nil, // DeviceEngagementBytes
		nil, // EReaderKeyBytes
		[]interface{}{ // BrowserHandover
			BROWSER_HANDOVER_V1,
			nonce,
			originInfoBytes,
			requesterIdHash,
		},
	}

	transcript, err := cbor.Marshal(browserHandover)
	if err != nil {
		return nil, fmt.Errorf("error encoding transcript: %v", err)
	}

	return transcript, nil
}

const ANDROID_HANDOVER_V1 = "AndroidHandoverv1"

func generateAndroidSessionTranscript(nonce []byte, packageName string, requesterIdHash []byte) ([]byte, error) {
	// Create the AndroidHandover array
	androidHandover := []interface{}{
		ANDROID_HANDOVER_V1,
		nonce,
		[]byte(packageName),
		requesterIdHash,
	}

	// Create the final CBOR array
	sessionTranscript := []interface{}{
		nil, // DeviceEngagementBytes
		nil, // EReaderKeyBytes
		androidHandover,
	}

	transcript, err := cbor.Marshal(sessionTranscript)
	if err != nil {
		return nil, fmt.Errorf("error encoding transcript: %v", err)
	}

	return transcript, nil
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
