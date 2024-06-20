package exchange_protocol

import (
	"crypto/ecdh"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"hash"

	"github.com/fxamacker/cbor/v2"
	"github.com/kokukuma/identity-credential-api-demo/internal/mdoc"
)

// https://github.com/openwallet-foundation-labs/identity-credential/blob/da5991c34f4d3356606e68b9376419c7f9c62cb3/appholder/src/main/java/com/android/identity/wallet/GetCredentialActivity.kt#L163

type IdentityRequestPreview struct {
	Selector        Selector `json:"selector"`
	Nonce           string   `json:"nonce"`
	ReaderPublicKey string   `json:"readerPublicKey"`
}

func (ir *IdentityRequestPreview) ApplyOption(option IdentityRequestOption) {
	option(ir)
}

type Selector struct {
	Format    []string  `json:"format"`
	Retention Retention `json:"retention"`
	DocType   string    `json:"doctype"`
	Fields    []Field   `json:"fields"`
}

type Field struct {
	Namespace      string `json:"namespace"`
	Name           string `json:"name"`
	IntentToRetain bool   `json:"intentToRetain"`
}

type Retention struct {
	Days int `json:"days"`
}

type PreviewData struct {
	Token string `json:"token"`
}

type AndroidHPKEV1 struct {
	Version              string               `json:"version"`
	CipherText           []byte               `json:"cipherText"`
	EncryptionParameters EncryptionParameters `json:"encryptionParameters"`
}

type EncryptionParameters struct {
	PKEM []byte `json:"pkEm"`
}

func parseHPKEEnvelope(a *AndroidHPKEV1) *HPKEEnvelope {
	return &HPKEEnvelope{
		Algorithm: a.Version,
		Params: HPKEParams{
			PkEM: a.EncryptionParameters.PKEM,
		},
		Data: a.CipherText,
	}
}

func ParsePreview(
	data, origin string,
	privateKey *ecdh.PrivateKey,
	nonceByte []byte) (*mdoc.DeviceResponse, error) {
	var msg PreviewData
	if err := json.Unmarshal([]byte(data), &msg); err != nil {
		return nil, fmt.Errorf("failed to parse data as JSON")
	}

	decoded, err := b64.DecodeString(msg.Token)
	if err != nil {
		return nil, fmt.Errorf("Error decoding Base64URL string: %v", err)
	}

	var claims AndroidHPKEV1
	if err := cbor.Unmarshal(decoded, &claims); err != nil {
		return nil, fmt.Errorf("Error unmarshal cbor string: %v", err)
	}

	// Decrypt the ciphertext
	info, err := generateBrowserSessionTranscript(nonceByte, origin, calcDigest(privateKey.PublicKey().Bytes(), "SHA-256"))
	if err != nil {
		return nil, fmt.Errorf("failed to create aad: %v", err)
	}

	plaintext, err := DecryptHPKE(parseHPKEEnvelope(&claims), privateKey.Bytes(), info)
	if err != nil {
		return nil, fmt.Errorf("Error decryptAndroidHPKEV1: %v", err)
	}

	var deviceResp mdoc.DeviceResponse
	if err := cbor.Unmarshal(plaintext, &deviceResp); err != nil {
		return nil, fmt.Errorf("Error unmarshal cbor string: %v", err)
	}

	return &deviceResp, nil
}

func calcDigest(message []byte, alg string) []byte {
	var hasher hash.Hash
	switch alg {
	case "SHA-256":
		hasher = sha256.New()
	// case "SHA-384":
	// 	hasher = sha384.New()
	case "SHA-512":
		hasher = sha512.New()
	}
	hasher.Write(message)
	return hasher.Sum(nil)
}
