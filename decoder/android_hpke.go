package decoder

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/kokukuma/mdoc-verifier/mdoc"
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
	if privateKey == nil {
		return nil, fmt.Errorf("private key must not be nil")
	}
	if len(sessTrans) == 0 {
		return nil, fmt.Errorf("session transcript must not be empty")
	}

	var msg PreviewData
	if err := json.Unmarshal([]byte(data), &msg); err != nil {
		return nil, fmt.Errorf("failed to parse data as JSON: %w", err)
	}

	decoded, err := base64.URLEncoding.WithPadding(base64.StdPadding).DecodeString(msg.Token)
	if err != nil {
		return nil, fmt.Errorf("failed to decode Base64URL string: %w", err)

	}

	var claims AndroidHPKEV1
	if err := cbor.Unmarshal(decoded, &claims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal CBOR data: %w", err)
	}

	plaintext, err := DecryptHPKE(claims.CipherText, claims.EncryptionParameters.PKEM, sessTrans, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt HPKE data: %w", err)
	}

	var devResp *mdoc.DeviceResponse
	if err := cbor.Unmarshal(plaintext, &devResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal device response: %w", err)
	}
	return devResp, nil
}
