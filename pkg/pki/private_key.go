package pki

import (
	"crypto/ecdh"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func LoadPrivateKey(dataPath string) (*ecdh.PrivateKey, error) {
	pemString, err := os.ReadFile(dataPath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode([]byte(pemString))
	if block == nil || block.Type != "EC PRIVATE KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}

	ecdsaPriv, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	curve := ecdh.P256()
	ecdhPriv, err := curve.NewPrivateKey(ecdsaPriv.D.Bytes())
	if err != nil {
		return nil, fmt.Errorf("Error converting to ECDH private key: %v", err)
	}
	return ecdhPriv, nil
}
