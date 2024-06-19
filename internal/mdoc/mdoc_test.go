package mdoc

import (
	"encoding/hex"
	"io/ioutil"
	"log"
	"path/filepath"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/fxamacker/cbor/v2"
)

func getPath(fileName string) (string, error) {
	dir, err := filepath.Abs(filepath.Dir("."))
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "testdata", fileName), nil
}

func TestMdocVerifyIssuerAuth(t *testing.T) {
	dataPath, err := getPath("plaintext_topics.cbor")
	if err != nil {
		log.Fatal("1", err)
	}

	plaintext, err := ioutil.ReadFile(dataPath)
	if err != nil {
		log.Fatal("2", err)
	}

	plaintextByte, err := hex.DecodeString(string(plaintext))
	if err != nil {
		log.Fatal(err)
	}

	rootCrtDataPath, err := getPath("/")
	if err != nil {
		log.Fatal("3", err)
	}

	roots, err := GetRootCertificates(rootCrtDataPath)
	if err != nil {
		log.Fatal("4", err)
	}

	// Apple's data format
	topics := struct {
		Identity DeviceResponse `json:"identity"`
	}{}

	spew.Dump(plaintextByte)

	if err := cbor.Unmarshal(plaintextByte, &topics); err != nil {
		log.Fatal("5", err)
	}

	spew.Dump(topics)

	t.Run("VerifyIssuerAuth", func(t *testing.T) {
		for _, doc := range topics.Identity.Documents {
			if err := doc.IssuerSigned.VerifyIssuerAuth(roots); err != nil {
				t.Fatalf("failed to verifyIssuserAuth %v", err)
			}

			_, err := doc.IssuerSigned.VerifiedElements()
			if err != nil {
				log.Fatal(err)
			}
			// for ns, items := range data {
			// 	spew.Dump(ns)
			// 	for _, item := range items {
			// 		spew.Dump(item.ElementIdentifier, item.ElementValue)
			// 	}
			// }
		}
	})
}
