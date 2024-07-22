package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/kokukuma/mdoc-verifier/apple_hpke"
	"github.com/kokukuma/mdoc-verifier/document"
	"github.com/kokukuma/mdoc-verifier/mdoc"
	"github.com/kokukuma/mdoc-verifier/pkg/pki"
)

var (
	// obtain from developer center beforehand
	merchantID          = "PassKit_Identity_Test_Merchant_ID"
	teamID              = "PassKit_Identity_Test_Team_ID"
	applePrivateKeyPath = "/Users/kokukuma/Downloads/identity_verification_sample/sample/merchant_encryption.key"

	// obtaine from apple document beforehand
	rootCerts = "/Users/kokukuma/Downloads/identity_verification_sample/sample/issuer_root.crt"

	// obtain from apple verify with wallet API response
	hpkeEnvelopeCborPath = "/Users/kokukuma/Downloads/identity_verification_sample/sample/hpke_envelope.cbor"

	// create by ourselvies
	nonceStr = "964c3e56a06061fa213fce2ba73217a6d359c2e65d44ec6b5b94f9c57eeeb3c045906344c7032e2609eb60533c35a98a75d0d2444ef9057c55cbb2d05d672a25"

	parsedTime, _ = time.Parse("2006-01-02", "2022-06-01")
)

func main() {
	mdoc.Now = parsedTime // For test

	data, nonce, err := loadSampleData()
	if err != nil {
		panic("failed to load sample data: " + err.Error())
	}

	roots, err := pki.GetRootCertificate(rootCerts)
	if err != nil {
		panic("failed to load rootCert: " + err.Error())
	}

	privKey, err := pki.LoadPrivateKey(applePrivateKeyPath)
	if err != nil {
		panic("failed to load private key: " + err.Error())
	}

	// deviceResponseのparse
	devResp, sessTrans, err := apple_hpke.ParseDeviceResponse(data, merchantID, teamID, privKey, nonce)
	if err != nil {
		panic("failed to parse device response: " + err.Error())
	}

	for _, doc := range devResp.Documents {

		// mdoc検証
		if err := mdoc.Verify(doc, sessTrans, roots, false, false); err != nil {
			panic("failed to verify mdoc: " + err.Error())
		}

		// element取得
		for _, elemName := range []document.ElementIdentifier{
			document.IsoFamilyName,
			document.IsoGivenName,
			document.IsoBirthDate,
		} {
			elemValue, err := doc.IssuerSigned.GetElementValue(document.ISO1801351, elemName)
			if err != nil {
				panic("failed to get element: " + err.Error())
			}
			spew.Dump(elemName, elemValue)
		}
	}
}

// AppleのSampleを取得
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
