package exchange_protocol

import (
	"fmt"

	"github.com/davecgh/go-spew/spew"
	"github.com/fxamacker/cbor/v2"
	"github.com/kokukuma/identity-credential-api-demo/internal/mdoc"
)

// https://developer.apple.com/documentation/passkit_apple_pay_and_wallet/wallet/verifying_wallet_identity_requests

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

// TODO:
// privateKeyByte, publicKeyByteは、[]byteじゃないほうがいいだろう...

func ParseApple(data []byte, merchantID, temaID string, privateKeyByte, publicKeyByte, nonceByte []byte) (*mdoc.DeviceResponse, error) {
	// var msg PreviewData
	// if err := json.Unmarshal([]byte(data), &msg); err != nil {
	// 	return nil, fmt.Errorf("failed to parse data as JSON")
	// }
	//
	// decoded, err := b64.DecodeString(data)
	// if err != nil {
	// 	return nil, fmt.Errorf("Error decoding Base64URL string: %v", err)
	// }

	var claims HPKEEnvelope
	if err := cbor.Unmarshal(data, &claims); err != nil {
		return nil, fmt.Errorf("Error unmarshal cbor string: %v", err)
	}
	spew.Dump(claims)

	// Decrypt the ciphertext
	info, err := generateAppleSessionTranscript(merchantID, temaID, nonceByte, calcDigest(publicKeyByte, "SHA-256"))
	if err != nil {
		return nil, fmt.Errorf("failed to create aad: %v", err)
	}

	plaintext, err := DecryptHPKE(&claims, privateKeyByte, info)
	if err != nil {
		return nil, fmt.Errorf("Error decryptAndroidHPKEV1: %v", err)
	}

	var deviceResp mdoc.DeviceResponse
	if err := cbor.Unmarshal(plaintext, &deviceResp); err != nil {
		return nil, fmt.Errorf("Error unmarshal cbor string: %v", err)
	}

	return &deviceResp, nil
}

const APPLE_HANDOVER_V1 = "AppleIdentityPresentment_1.0"

func generateAppleSessionTranscript(merchantID, temaID string, nonce, requesterIdHash []byte) ([]byte, error) {
	// Create the final CBOR array
	appleHandover := []interface{}{
		nil, // DeviceEngagementBytes
		nil, // EReaderKeyBytes
		[]interface{}{ // AppleHandover
			APPLE_HANDOVER_V1,
			nonce,
			merchantID,
			temaID,
			requesterIdHash,
		},
	}

	transcript, err := cbor.Marshal(appleHandover)
	if err != nil {
		return nil, fmt.Errorf("error encoding transcript: %v", err)
	}

	return transcript, nil
}
