package preview_hpke

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/kokukuma/mdoc-verifier/mdoc"
	"github.com/kokukuma/mdoc-verifier/pkg/hpke"
)

var (
	b64 = base64.URLEncoding.WithPadding(base64.StdPadding)
)

// https://github.com/openwallet-foundation-labs/identity-credential/blob/da5991c34f4d3356606e68b9376419c7f9c62cb3/appholder/src/main/java/com/android/identity/wallet/GetCredentialActivity.kt#L163

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

func ParseTokenResponse(data string) (*PreviewData, error) {
	var msg PreviewData
	if err := json.Unmarshal([]byte(data), &msg); err != nil {
		return nil, fmt.Errorf("failed to parse data as JSON")
	}
	return &msg, nil
}

func ParseDeviceResponse(
	msg *PreviewData,
	privateKey *ecdh.PrivateKey,
	sessTrans []byte,
) (*mdoc.DeviceResponse, error) {

	decoded, err := b64.DecodeString(msg.Token)
	if err != nil {
		return nil, fmt.Errorf("Error decoding Base64URL string: %v", err)
	}

	var claims AndroidHPKEV1
	if err := cbor.Unmarshal(decoded, &claims); err != nil {
		return nil, fmt.Errorf("Error unmarshal cbor string: %v", err)
	}

	plaintext, err := hpke.DecryptHPKE(claims.CipherText, claims.EncryptionParameters.PKEM, sessTrans, privateKey)
	if err != nil {
		return nil, fmt.Errorf("Error decryptAndroidHPKEV1: %v", err)
	}

	var deviceResp mdoc.DeviceResponse
	if err := cbor.Unmarshal(plaintext, &deviceResp); err != nil {
		return nil, fmt.Errorf("Error unmarshal cbor string: %v", err)
	}

	return &deviceResp, nil
}
