package hpke

import (
	"crypto/ecdh"
	"fmt"

	"github.com/cisco/go-hpke"
)

func DecryptHPKE(data, pkEM, info []byte, privKey *ecdh.PrivateKey) ([]byte, error) {

	// Initialize the HPKE context
	suite, err := hpke.AssembleCipherSuite(hpke.DHKEM_P256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AESGCM128)
	if err != nil {
		return nil, fmt.Errorf("error assembling cipher suite: %v", err)
	}

	// Deserialize the recipient's private key
	skR, err := suite.KEM.DeserializePrivateKey(privKey.Bytes())
	if err != nil {
		return nil, fmt.Errorf("error deserializing private key: %v", err)
	}

	// Setup the HPKE receiver context using SetupBaseR
	ctxR, err := hpke.SetupBaseR(suite, skR, pkEM, info)
	if err != nil {
		return nil, fmt.Errorf("error setting up receiver context: %v", err)
	}

	plainText, err := ctxR.Open(nil, data) // No associated data
	if err != nil {
		return nil, fmt.Errorf("error decrypting ciphertext: %v", err)
	}

	return plainText, nil
}
