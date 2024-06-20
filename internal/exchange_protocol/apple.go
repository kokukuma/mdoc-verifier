package exchange_protocol

import (
	"bytes"
	"crypto/ecdh"
	"fmt"

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

func ParseApple(
	data []byte,
	merchantID, temaID string,
	privateKey *ecdh.PrivateKey,
	nonceByte []byte) (*mdoc.DeviceResponse, error) {

	var claims HPKEEnvelope
	if err := cbor.Unmarshal(data, &claims); err != nil {
		return nil, fmt.Errorf("Error unmarshal cbor string: %v", err)
	}

	// Decrypt the ciphertext
	info, err := generateAppleSessionTranscript(merchantID, temaID, nonceByte, calcDigest(privateKey.PublicKey().Bytes(), "SHA-256"))
	if err != nil {
		return nil, fmt.Errorf("failed to create aad: %v", err)
	}

	if !bytes.Equal(calcDigest(info, "SHA-256"), claims.Params.InfoHash) {
		return nil, fmt.Errorf("infoHash is not match: %v != %v", calcDigest(info, "SHA-256"), claims.Params.InfoHash)
	}

	if !bytes.Equal(calcDigest(privateKey.PublicKey().Bytes(), "SHA-256"), claims.Params.PkRHash) {
		return nil, fmt.Errorf("PkRHash is not match")
	}

	plaintext, err := DecryptHPKE(&claims, privateKey.Bytes(), info)
	if err != nil {
		return nil, fmt.Errorf("Error DecryptHPKE: %v", err)
	}

	topics := struct {
		Identity mdoc.DeviceResponse `json:"identity"`
	}{}

	if err := cbor.Unmarshal(plaintext, &topics); err != nil {
		return nil, fmt.Errorf("Error unmarshal cbor string: %v", err)
	}

	return &topics.Identity, nil
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
