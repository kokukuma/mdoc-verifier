package decrypter

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/kokukuma/mdoc-verifier/mdoc"
)

var (
	b64 = base64.URLEncoding.WithPadding(base64.StdPadding)
)

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

func AndroidHPKE(
	data string,
	privateKey *ecdh.PrivateKey,
	sessTrans []byte,
) (*mdoc.DeviceResponse, error) {
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

	plaintext, err := DecryptHPKE(claims.CipherText, claims.EncryptionParameters.PKEM, sessTrans, privateKey)
	if err != nil {
		return nil, fmt.Errorf("Error decryptAndroidHPKEV1: %v", err)
	}

	var devResp *mdoc.DeviceResponse
	if err := cbor.Unmarshal(plaintext, &devResp); err != nil {
		return nil, fmt.Errorf("Error unmarshal cbor string: %v", err)
	}
	return devResp, nil
}
