package main

import (
	"crypto/ecdh"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/kokukuma/mdoc-verifier/apple_hpke"
	"github.com/kokukuma/mdoc-verifier/document"
	"github.com/kokukuma/mdoc-verifier/mdoc"
	"github.com/kokukuma/mdoc-verifier/pkg/hash"
	"github.com/kokukuma/mdoc-verifier/pkg/pki"
	"github.com/kokukuma/mdoc-verifier/session_transcript"
)

var (
	// obtain from developer center beforehand
	merchantID          = "PassKit_Identity_Test_Merchant_ID"
	teamID              = "PassKit_Identity_Test_Team_ID"
	applePrivateKeyPath = "/Users/kokukuma/Downloads/identity_verification_sample/sample/merchant_encryption.key"

	// obtaine from apple document beforehand
	rootCerts = "/Users/kokukuma/Downloads/identity_verification_sample/sample/issuer_root.crt"

	// create by ourselvies
	nonceStr = "964c3e56a06061fa213fce2ba73217a6d359c2e65d44ec6b5b94f9c57eeeb3c045906344c7032e2609eb60533c35a98a75d0d2444ef9057c55cbb2d05d672a25"

	// obtain from apple verify with wallet API response
	hpkeEnvelopeCborPath = "/Users/kokukuma/Downloads/identity_verification_sample/sample/hpke_envelope.cbor"

	//
	data, nonce []byte
	roots       *x509.CertPool
	privKey     *ecdh.PrivateKey
)

func init() {
	var err error

	data, nonce, err = loadSampleData()
	if err != nil {
		panic("failed to load sample data: " + err.Error())
	}

	roots, err = pki.GetRootCertificate(rootCerts)
	if err != nil {
		panic("failed to load rootCert: " + err.Error())
	}

	privKey, err = pki.LoadPrivateKey(applePrivateKeyPath)
	if err != nil {
		panic("failed to load private key: " + err.Error())
	}
}

func main() {
	// sessTrans will be used to decrypt HPKEEnvelope and mdoc verification.
	sessTrans, err := session_transcript.AppleHandoverV1(merchantID, teamID, nonce, hash.Digest(privKey.PublicKey().Bytes(), "SHA-256"))
	if err != nil {
		panic("failed to get session transcript: " + err.Error())
	}

	// Parse HPKEEnvelope into data model of ISO/IEC 18013-5
	devResp, err := apple_hpke.ParseDataToDeviceResp(data, privKey, sessTrans)
	if err != nil {
		panic("failed to parse device response: " + err.Error())
	}

	docIsoMDL, err := devResp.GetDocument(document.IsoMDL)
	if err != nil {
		panic("failed to get document: " + err.Error())
	}

	date, _ := time.Parse("2006-01-02", "2022-06-01")
	if err := mdoc.NewVerifier(roots, mdoc.WithSignCurrentTime(date), mdoc.WithCertCurrentTime(date)).Verify(docIsoMDL, sessTrans); err != nil {
		panic("failed to verify mdoc: " + err.Error())
	}

	for _, elemName := range []document.ElementIdentifier{
		document.IsoFamilyName,
		document.IsoGivenName,
		document.IsoBirthDate,
		document.IsoResidentCity,
		document.IsoDocumentNumber,
	} {
		elemValue, err := docIsoMDL.IssuerSigned.GetElementValue(document.ISO1801351, elemName)
		if err != nil {
			panic("failed to get element: " + err.Error())
		}
		fmt.Println(elemName, ":", elemValue)
	}
}

// This sample data is provided from Apple developer page.
func loadSampleData() ([]byte, []byte, error) {
	dataStr, err := os.ReadFile(hpkeEnvelopeCborPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load data: %v", err)
	}
	contentString := string(dataStr)
	contentWithoutNewlines := strings.ReplaceAll(contentString, "\n", "")
	contentWithoutNewlines = strings.ReplaceAll(contentWithoutNewlines, "\r", "")

	sampleHpkeEnvelope, err := hex.DecodeString(contentWithoutNewlines)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode data: %v", err)
	}

	nonce, err := hex.DecodeString(nonceStr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode nonce: %v", err)
	}

	return sampleHpkeEnvelope, nonce, nil
}
