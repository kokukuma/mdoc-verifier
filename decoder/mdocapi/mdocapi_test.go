package mdocapi

import (
	"crypto/ecdh"
	"crypto/rand"
	"testing"

	"github.com/kokukuma/mdoc-verifier/mdoc"
)

func TestPrepareEncryptionInfo(t *testing.T) {
	// Generate test key pair
	curve := ecdh.P256()
	privateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	nonce := []byte("test-nonce-12345")
	origin := "https://example.com"

	encInfo, sessTrans, err := PrepareEncryptionInfo(nonce, privateKey.PublicKey(), origin)
	if err != nil {
		t.Fatalf("PrepareEncryptionInfo failed: %v", err)
	}

	t.Logf("EncryptionInfo length: %d", len(encInfo))
	t.Logf("SessionTranscript length: %d", len(sessTrans))

	if len(encInfo) == 0 {
		t.Error("EncryptionInfo should not be empty")
	}
	if len(sessTrans) == 0 {
		t.Error("SessionTranscript should not be empty")
	}
}

func TestCreateRequest(t *testing.T) {
	// Generate test key pair
	curve := ecdh.P256()
	privateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	nonce := []byte("test-nonce-12345")
	origin := "https://example.com"

	// Prepare encryption info first
	_, sessTrans, err := PrepareEncryptionInfo(nonce, privateKey.PublicKey(), origin)
	if err != nil {
		t.Fatalf("PrepareEncryptionInfo failed: %v", err)
	}

	// Create doc requests
	docRequests := []DocRequestInput{
		{
			DocType: mdoc.DocType("org.iso.18013.5.1.mDL"),
			Namespaces: map[mdoc.NameSpace]map[mdoc.ElementIdentifier]bool{
				"org.iso.18013.5.1": {
					"family_name": true,
					"given_name":  true,
				},
			},
		},
	}

	// Test without signing (nil readerKey)
	req, deviceRequestBytes, err := CreateRequest(docRequests, sessTrans, nil, nil)
	if err != nil {
		t.Fatalf("CreateRequest failed: %v", err)
	}

	t.Logf("DeviceRequest: %s", req.DeviceRequest)
	t.Logf("DeviceRequest bytes length: %d", len(deviceRequestBytes))

	if req.DeviceRequest == "" {
		t.Error("DeviceRequest should not be empty")
	}
}

func TestCreateFullRequest(t *testing.T) {
	// Generate test key pair
	curve := ecdh.P256()
	privateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	nonce := []byte("test-nonce-12345")
	origin := "https://example.com"

	// Create doc requests
	docRequests := []DocRequestInput{
		{
			DocType: mdoc.DocType("org.iso.18013.5.1.mDL"),
			Namespaces: map[mdoc.NameSpace]map[mdoc.ElementIdentifier]bool{
				"org.iso.18013.5.1": {
					"family_name": true,
					"given_name":  true,
				},
			},
		},
	}

	// Test without signing
	req, encInfo, err := CreateFullRequest(nonce, privateKey.PublicKey(), origin, docRequests, nil, nil)
	if err != nil {
		t.Fatalf("CreateFullRequest failed: %v", err)
	}

	t.Logf("DeviceRequest: %s", req.DeviceRequest)
	t.Logf("EncryptionInfo: %s", req.EncryptionInfo)
	t.Logf("EncryptionInfo bytes length: %d", len(encInfo))

	if req.DeviceRequest == "" {
		t.Error("DeviceRequest should not be empty")
	}
	if req.EncryptionInfo == "" {
		t.Error("EncryptionInfo should not be empty")
	}
}
