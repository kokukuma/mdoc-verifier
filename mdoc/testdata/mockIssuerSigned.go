package testdata

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"

	"github.com/veraison/go-cose"
)

// Define necessary types and constants for testing (replace with your actual definitions)
type IssuerNameSpaces map[string]string

type IssuerSigned struct {
	NameSpaces IssuerNameSpaces          `json:"nameSpaces,omitempty"`
	IssuerAuth cose.UntaggedSign1Message `json:"issuerAuth"`
}

// Mock Alg and DocumentSigningKey methods for testing
func (is IssuerSigned) Alg() (cose.Algorithm, error) {
	// Use a known algorithm for testing
	return cose.AlgorithmES256, nil
}

func (is IssuerSigned) DocumentSigningKey() (interface{}, error) {
	// Generate a test key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &privateKey.PublicKey, nil
}
