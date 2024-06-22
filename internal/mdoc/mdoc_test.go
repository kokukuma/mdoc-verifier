package mdoc

import (
	"encoding/hex"
	"log"
	"os"
	"path/filepath"
	"testing"
	"time"

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

func getPlaintext(fileName string) ([]byte, error) {
	dataPath, err := getPath(fileName)
	if err != nil {
		return nil, err
	}

	plaintext, err := os.ReadFile(dataPath)
	if err != nil {
		return nil, err
	}

	plaintextByte, err := hex.DecodeString(string(plaintext))
	if err != nil {
		return nil, err
	}
	return plaintextByte, nil
}

func TestMdocVerifyIssuerAuth(t *testing.T) {
	plaintextByte, err := getPlaintext("plaintext_topics.cbor")
	if err != nil {
		log.Fatal("3", err)
	}

	sessionTranscript, err := getPlaintext("session_transcript.txt")
	if err != nil {
		log.Fatal("3", err)
	}

	rootCrtDataPath, err := getPath("/")
	if err != nil {
		log.Fatal("3", err)
	}

	roots, err := GetRootCertificates(rootCrtDataPath)
	if err != nil {
		log.Fatal("4", err)
	}
	spew.Dump(roots)

	// Apple's data format
	topics := struct {
		Identity DeviceResponse `json:"identity"`
	}{}

	if err := cbor.Unmarshal(plaintextByte, &topics); err != nil {
		log.Fatal("5", err)
	}

	parsedTime, err := time.Parse("2006-01-02", "2022-06-01")
	if err != nil {
		log.Fatal("5", err)
	}

	t.Run("VerifyIssuerAuth", func(t *testing.T) {
		for _, doc := range topics.Identity.Documents {
			mso, err := doc.IssuerSigned.GetMobileSecurityObject(parsedTime)
			if err != nil {
				t.Fatalf("failed to get mso %v", err)
			}

			if err := VerifyIssuerAuth(doc.IssuerSigned.IssuerAuth, roots, false); err != nil {
				t.Fatalf("failed to verifyIssuserAuth %v", err)
			}

			if err := VerifyDeviceSigned(mso, doc, sessionTranscript); err != nil {
				spew.Dump("-------- VerifyDeviceSigned")
				t.Fatalf("failed to VerifyDeviceSigned  %v", err)
			}

			_, err = VerifiedElements(doc.IssuerSigned.NameSpaces, mso)
			if err != nil {
				t.Fatalf("failed to VerifiedElements %v", err)
			}
			spew.Dump(mso.ValidityInfo)
			spew.Dump(doc.DeviceSigned)
			// for ns, items := range data {
			// 	spew.Dump(ns)
			// 	for _, item := range items {
			// 		spew.Dump(item.ElementIdentifier, item.ElementValue)
			// 	}
			// }
		}
	})
}
