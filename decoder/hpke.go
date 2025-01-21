package decoder

import (
	"crypto/ecdh"
	"fmt"

	"github.com/cisco/go-hpke"
)

const (
	kemAlg  = hpke.DHKEM_P256
	kdfAlg  = hpke.KDF_HKDF_SHA256
	aeadAlg = hpke.AEAD_AESGCM128
)

func DecryptHPKE(data, pkEM, info []byte, privKey *ecdh.PrivateKey) ([]byte, error) {

	if len(data) == 0 {
		return nil, fmt.Errorf("empty data")
	}
	if len(pkEM) == 0 {
		return nil, fmt.Errorf("empty ephemeral public key")
	}
	if privKey == nil {
		return nil, fmt.Errorf("nil private key")
	}

	// Initialize the HPKE context
	suite, err := hpke.AssembleCipherSuite(kemAlg, kdfAlg, aeadAlg)
	if err != nil {
		return nil, fmt.Errorf("failed to assemble cipher suite: %w", err)

	}

	// Deserialize the recipient's private key
	skR, err := suite.KEM.DeserializePrivateKey(privKey.Bytes())
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize private key: %w", err)
	}

	// Setup the HPKE receiver context using SetupBaseR
	ctxR, err := hpke.SetupBaseR(suite, skR, pkEM, info)
	if err != nil {
		return nil, fmt.Errorf("failed to setup receiver context: %w", err)
	}

	plainText, err := ctxR.Open(nil, data) // No associated data
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt ciphertext: %w", err)
	}

	return plainText, nil
}
