package apple_hpke

import (
	"bytes"
	"crypto/ecdh"
	"encoding/hex"
	"log"
	"os"
	"path/filepath"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/kokukuma/mdoc-verifier/pkg/hash"
	"github.com/kokukuma/mdoc-verifier/pkg/pki"
)

var (
	nonce             = "964c3e56a06061fa213fce2ba73217a6d359c2e65d44ec6b5b94f9c57eeeb3c045906344c7032e2609eb60533c35a98a75d0d2444ef9057c55cbb2d05d672a25"
	infoHash          = "59a47fc9fa2402cfefa5e889183d4222cb15bb10807e53d90b4eef5eb9ff1d96"
	sessionTranscript = "83f6f685781c4170706c654964656e7469747950726573656e746d656e745f312e305840964c3e56a06061fa213fce2ba73217a6d359c2e65d44ec6b5b94f9c57eeeb3c045906344c7032e2609eb60533c35a98a75d0d2444ef9057c55cbb2d05d672a257821506173734b69745f4964656e746974795f546573745f4d65726368616e745f4944781d506173734b69745f4964656e746974795f546573745f5465616d5f49445820b2c00f06b2df645691174f1331ade35141f17e19b3021d07560b4a71fc61818c"
	merchantID        = "PassKit_Identity_Test_Merchant_ID"
	teamID            = "PassKit_Identity_Test_Team_ID"

	nonceByte, infoHashByte []byte
)

func setup() {
	var err error
	infoHashByte, err = hex.DecodeString(infoHash)
	if err != nil {
		log.Fatal(err)
	}
	nonceByte, err = hex.DecodeString(nonce)
	if err != nil {
		log.Fatal(err)
	}
}

func getPath(fileName string) (string, error) {
	dir, err := filepath.Abs(filepath.Dir("."))
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "testdata", fileName), nil
}

func loadPrivateKeyForTest() (*ecdh.PrivateKey, error) {
	dataPath, err := getPath("merchant_encryption.key")
	if err != nil {
		return nil, err
	}
	return pki.LoadPrivateKey(dataPath)
}

func TestParseDeviceResponse(t *testing.T) {
	setup()

	dataPath, err := getPath("hpke_envelope.cbor")
	if err != nil {
		t.Fatal(err)
	}

	hexString, err := os.ReadFile(dataPath)
	if err != nil {
		t.Fatal(err)
	}

	sampleHpkeEnvelope, err := hex.DecodeString(string(hexString))
	if err != nil {
		log.Fatal(err)
	}

	privKey, err := loadPrivateKeyForTest()
	if err != nil {
		log.Fatal(err)
	}

	publicKeyByte := privKey.PublicKey().Bytes()

	sessTrans, _ := SessionTranscript(merchantID, teamID, nonceByte, hash.Digest(publicKeyByte, "SHA-256"))

	t.Run("ParseApple", func(t *testing.T) {
		deviceResp, err := ParseDataToDeviceResp(sampleHpkeEnvelope, privKey, sessTrans)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		spew.Dump(deviceResp)
		if deviceResp.Version != "1.0" {
			t.Fatalf("different version: %v != 1.0", deviceResp.Version)
		}
	})
}

func TestGenerateAppleSessionTranscript(t *testing.T) {
	setup()

	privKey, err := loadPrivateKeyForTest()
	if err != nil {
		log.Fatal(err)
	}

	publicKeyByte := privKey.PublicKey().Bytes()

	t.Run("generateAppleSessionTranscript", func(t *testing.T) {
		actual, err := SessionTranscript(merchantID, teamID, nonceByte, hash.Digest(publicKeyByte, "SHA-256"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if sessionTranscript != hex.EncodeToString(actual) {
			t.Fatalf("info is unmatched: %v != %v", sessionTranscript, string(actual))
		}
		if !bytes.Equal(infoHashByte, hash.Digest(actual, "SHA-256")) {
			t.Fatalf("infohash is unmatched: %v != %v", infoHashByte, hash.Digest(actual, "SHA-256"))
		}
	})
}

func TestPublickey(t *testing.T) {
	setup()

	privKey, err := loadPrivateKeyForTest()
	if err != nil {
		log.Fatal(err)
	}

	publicKeyByte := privKey.PublicKey().Bytes()

	pubByteSample, _ := hex.DecodeString("b2c00f06b2df645691174f1331ade35141f17e19b3021d07560b4a71fc61818c")
	if !bytes.Equal(pubByteSample, hash.Digest(publicKeyByte, "SHA-256")) {
		t.Fatalf("info is unmatched")
	}
}
