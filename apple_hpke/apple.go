package apple_hpke

import (
	"bytes"
	"crypto/ecdh"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/fxamacker/cbor/v2"
	"github.com/kokukuma/identity-credential-api-demo/mdoc"
	"github.com/kokukuma/identity-credential-api-demo/protocol"
)

var (
	b64 = base64.URLEncoding.WithPadding(base64.NoPadding)
)

// https://developer.apple.com/documentation/passkit_apple_pay_and_wallet/wallet/verifying_wallet_identity_requests

type IdentityRequestApple struct {
	Nonce string `json:"nonce"`
}

func loadPrivateKey(dataPath string) (*ecdh.PrivateKey, error) {
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

func BeginIdentityRequest(privKeyPath string) (*IdentityRequestApple, *protocol.SessionData, error) {
	privKey, err := loadPrivateKey(privKeyPath)
	if err != nil {
		return nil, nil, err
	}
	nonce, err := protocol.CreateNonce()
	if err != nil {
		return nil, nil, err
	}

	return &IdentityRequestApple{
			Nonce: nonce.String(),
		}, &protocol.SessionData{
			Nonce:      nonce,
			PrivateKey: privKey,
		}, nil
}

type HPKEEnvelope struct {
	Algorithm string     `json:"algorithm"`
	Params    HPKEParams `json:"params"`
	Data      []byte     `json:"data"`
}

type HPKEParams struct {
	Mode     uint   `json:"mode"`
	PkEM     []byte `json:"pkEm"`
	PkRHash  []byte `json:"pkRHash"`
	InfoHash []byte `json:"infoHash"`
}

func ParseDeviceResponse(
	data string,
	merchantID, temaID string,
	privateKey *ecdh.PrivateKey,
	nonceByte []byte) (*mdoc.DeviceResponse, []byte, error) {

	decoded, err := b64.DecodeString(data)
	if err != nil {
		return nil, nil, fmt.Errorf("Error decoding Base64URL string: %v", err)
	}

	var claims HPKEEnvelope
	if err := cbor.Unmarshal(decoded, &claims); err != nil {
		return nil, nil, fmt.Errorf("Error unmarshal cbor as HPKEEnvelope: %v", err)
	}

	// Decrypt the ciphertext
	info, err := generateAppleSessionTranscript(merchantID, temaID, nonceByte, protocol.Digest(privateKey.PublicKey().Bytes(), "SHA-256"))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create aad: %v", err)
	}

	if !bytes.Equal(protocol.Digest(info, "SHA-256"), claims.Params.InfoHash) {
		return nil, nil, fmt.Errorf("infoHash is not match: %v != %v", protocol.Digest(info, "SHA-256"), claims.Params.InfoHash)
	}

	if !bytes.Equal(protocol.Digest(privateKey.PublicKey().Bytes(), "SHA-256"), claims.Params.PkRHash) {
		return nil, nil, fmt.Errorf("PkRHash is not match")
	}

	plaintext, err := protocol.DecryptHPKE(claims.Data, claims.Params.PkEM, info, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("Error DecryptHPKE: %v", err)
	}

	fmt.Println(hex.EncodeToString(plaintext))

	topics := struct {
		Identity mdoc.DeviceResponse `json:"identity"`
	}{}

	if err := cbor.Unmarshal(plaintext, &topics); err != nil {
		return nil, nil, fmt.Errorf("Error unmarshal cbor as Identity: %v", err)
	}

	return &topics.Identity, info, nil
}
