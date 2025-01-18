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
	"github.com/kokukuma/mdoc-verifier/document"
	"github.com/kokukuma/mdoc-verifier/pkg/pki"
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

	roots, err := pki.GetRootCertificates(rootCrtDataPath)
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

	parsedTime, _ := time.Parse("2006-01-02", "2022-06-01")

	t.Run("Verify", func(t *testing.T) {
		for _, doc := range topics.Identity.Documents {
			if err := NewVerifier(roots, WithSignCurrentTime(parsedTime), WithCertCurrentTime(parsedTime)).Verify(&doc, sessionTranscript); err != nil {
				t.Fatalf("failed to Verify %v", err)
			}
		}
	})
}

func TestGetDocument(t *testing.T) {
	docType := document.DocType("testDoc")
	doc := Document{DocType: docType}
	resp := DeviceResponse{Documents: []Document{doc}}

	retrievedDoc, err := resp.GetDocument(docType)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if retrievedDoc.DocType != docType {
		t.Fatalf("Expected docType %v, got %v", docType, retrievedDoc.DocType)
	}
}
