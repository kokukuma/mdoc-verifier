package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"

	"github.com/kokukuma/identity-credential-api-demo/internal/cryptoroot"
)

type JWKS struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid []byte `json:"kid"`
}

func ecdsaPublicKeyToJWKS(publicKey *ecdsa.PublicKey) (JWKS, error) {
	jwk := JWK{
		Kty: "EC",
		Crv: getCurveName(publicKey.Curve),
		X:   base64.RawURLEncoding.EncodeToString(publicKey.X.Bytes()),
		Y:   base64.RawURLEncoding.EncodeToString(publicKey.Y.Bytes()),
		Alg: "ECDH-ES",
		Use: "enc",
		Kid: cryptoroot.CalcKID(publicKey, "sha256"),
	}

	jwks := JWKS{
		Keys: []JWK{jwk},
	}

	return jwks, nil
}

func getCurveName(curve elliptic.Curve) string {
	switch curve {
	case elliptic.P256():
		return "P-256"
	case elliptic.P384():
		return "P-384"
	case elliptic.P521():
		return "P-521"
	default:
		return "unknown"
	}
}
