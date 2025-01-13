package decoder

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/cisco/go-hpke"
)

func TestDecryptHPKE(t *testing.T) {
	// Test data
	data := []byte("plaintext")
	info := []byte("context info")
	// Generate a private key
	privKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("error generating private key: %v", err)
	}
	// Encrypt data for testing
	suite, err := hpke.AssembleCipherSuite(hpke.DHKEM_P256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AESGCM128)
	if err != nil {
		t.Fatalf("error assembling cipher suite: %v", err)
	}
	pkR := privKey.PublicKey()

	kemPubKey, err := suite.KEM.DeserializePublicKey(pkR.Bytes())
	if err != nil {
		t.Fatalf("failed to deserialize KEM public key: %v", err)
	}

	enc, ctxS, err := hpke.SetupBaseS(suite, rand.Reader, kemPubKey, info)
	if err != nil {
		t.Fatalf("error setting up sender context: %v", err)
	}
	ciphertext := ctxS.Seal(nil, data)
	// Call DecryptHPKE function
	decrypted, err := DecryptHPKE(ciphertext, enc, info, privKey)
	if err != nil {
		t.Fatalf("error decrypting ciphertext: %v", err)
	}
	// Check if the decrypted data matches the original data
	if !bytes.Equal(decrypted, data) {
		t.Errorf("expected %s, got %s", hex.EncodeToString(data), hex.EncodeToString(decrypted))
	}
}
