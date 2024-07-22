package apple_hpke

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/kokukuma/mdoc-verifier/mdoc"
	"github.com/kokukuma/mdoc-verifier/pkg/hash"
	"github.com/kokukuma/mdoc-verifier/pkg/hpke"
)

var (
	b64 = base64.URLEncoding.WithPadding(base64.NoPadding)
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

// 基本的にはこれがメイン
func ParseDeviceResponse(
	data []byte,
	merchantID, temaID string,
	privateKey *ecdh.PrivateKey,
	nonceByte []byte) (*mdoc.DeviceResponse, []byte, error) {

	var claims HPKEEnvelope
	if err := cbor.Unmarshal(data, &claims); err != nil {
		return nil, nil, fmt.Errorf("Error unmarshal cbor as HPKEEnvelope: %v", err)
	}

	// Decrypt the ciphertext
	info, err := generateAppleSessionTranscript(merchantID, temaID, nonceByte, hash.Digest(privateKey.PublicKey().Bytes(), "SHA-256"))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create aad: %v", err)
	}

	if !bytes.Equal(hash.Digest(info, "SHA-256"), claims.Params.InfoHash) {
		return nil, nil, fmt.Errorf("infoHash is not match: %v != %v", hash.Digest(info, "SHA-256"), claims.Params.InfoHash)
	}

	if !bytes.Equal(hash.Digest(privateKey.PublicKey().Bytes(), "SHA-256"), claims.Params.PkRHash) {
		return nil, nil, fmt.Errorf("PkRHash is not match")
	}

	plaintext, err := hpke.DecryptHPKE(claims.Data, claims.Params.PkEM, info, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("Error DecryptHPKE: %v", err)
	}

	topics := struct {
		Identity mdoc.DeviceResponse `json:"identity"`
	}{}

	if err := cbor.Unmarshal(plaintext, &topics); err != nil {
		return nil, nil, fmt.Errorf("Error unmarshal cbor as Identity: %v", err)
	}

	return &topics.Identity, info, nil
}
