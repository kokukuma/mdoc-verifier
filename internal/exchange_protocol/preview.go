package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/cisco/go-hpke"
	"github.com/fxamacker/cbor/v2"
)

// https://github.com/openwallet-foundation-labs/identity-credential/blob/da5991c34f4d3356606e68b9376419c7f9c62cb3/appholder/src/main/java/com/android/identity/wallet/GetCredentialActivity.kt#L163

var (
	b64 = base64.URLEncoding.WithPadding(base64.StdPadding)
)

type IdentityRequestPreview struct {
	Selector        Selector `json:"selector"`
	Nonce           string   `json:"nonce"`
	ReaderPublicKey string   `json:"readerPublicKey"`
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

func ParsePreview(data, origin string) (*DeviceResponse, error) {
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

	plaintext, err := DecryptAndroidHPKEV1(&claims, privateKey, publicKey, nonce, origin)
	if err != nil {
		return nil, fmt.Errorf("Error decryptAndroidHPKEV1: %v", err)
	}

	var deviceResp DeviceResponse
	if err := cbor.Unmarshal(plaintext, &deviceResp); err != nil {
		return nil, fmt.Errorf("Error unmarshal cbor string: %v", err)
	}

	return &deviceResp, nil
}

// DecryptAndroidHPKEV1 decrypts the CipherText in the AndroidHPKEV1 struct using the provided recipient private key
func DecryptAndroidHPKEV1(claims *AndroidHPKEV1, recipientPrivKey, recipientPubKey, nonceStr, origin string) ([]byte, error) {
	// Decode base64 encoded recipient private key to byte slice
	//privKey, err := base64.StdEncoding.DecodeString(recipientPrivKey)
	privKey, err := b64.DecodeString(recipientPrivKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode recipient private key: %v", err)
	}

	pubKey, err := b64.DecodeString(recipientPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode recipient private key: %v", err)
	}

	nonce, err := b64.DecodeString(nonceStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode recipient private key: %v", err)
	}

	// Initialize the HPKE context
	suite, err := hpke.AssembleCipherSuite(hpke.DHKEM_P256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AESGCM128)
	if err != nil {
		return nil, fmt.Errorf("error assembling cipher suite: %v", err)
	}

	// Deserialize the recipient's private key
	skR, err := suite.KEM.DeserializePrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("error deserializing private key: %v", err)
	}

	// Decrypt the ciphertext
	aad, err := generateBrowserSessionTranscript(nonce, origin, calcDigest(pubKey, "SHA-256"))
	if err != nil {
		return nil, fmt.Errorf("failed to create aad: %v", err)
	}

	// Setup the HPKE receiver context using SetupBaseR
	ctxR, err := hpke.SetupBaseR(suite, skR, claims.EncryptionParameters.PKEM, aad)
	if err != nil {
		return nil, fmt.Errorf("error setting up receiver context: %v", err)
	}

	plainText, err := ctxR.Open(nil, claims.CipherText) // No associated data
	if err != nil {
		return nil, fmt.Errorf("error decrypting ciphertext: %v", err)
	}

	// Print or process the decrypted plaintext as needed
	fmt.Printf("Decrypted text: %s\n", base64.URLEncoding.EncodeToString(plainText))

	return plainText, nil
}
