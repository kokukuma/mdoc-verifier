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
	b64 = base64.URLEncoding.WithPadding(base64.StdPadding)
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

func ParseHPKEEnvelope(data []byte) (*HPKEEnvelope, error) {
	var claims HPKEEnvelope
	if err := cbor.Unmarshal(data, &claims); err != nil {
		return nil, fmt.Errorf("Error unmarshal cbor as HPKEEnvelope: %v", err)
	}

	return &claims, nil
}

func ParseDeviceResponse(
	claims *HPKEEnvelope,
	privateKey *ecdh.PrivateKey,
	sessTrans []byte,
) (*mdoc.DeviceResponse, error) {

	if !bytes.Equal(hash.Digest(sessTrans, "SHA-256"), claims.Params.InfoHash) {
		return nil, fmt.Errorf("infoHash is not match: %v != %v", hash.Digest(sessTrans, "SHA-256"), claims.Params.InfoHash)
	}

	if !bytes.Equal(hash.Digest(privateKey.PublicKey().Bytes(), "SHA-256"), claims.Params.PkRHash) {
		return nil, fmt.Errorf("PkRHash is not match")
	}

	plaintext, err := hpke.DecryptHPKE(claims.Data, claims.Params.PkEM, sessTrans, privateKey)
	if err != nil {
		return nil, fmt.Errorf("Error DecryptHPKE: %v", err)
	}

	topics := struct {
		Identity mdoc.DeviceResponse `json:"identity"`
	}{}

	if err := cbor.Unmarshal(plaintext, &topics); err != nil {
		return nil, fmt.Errorf("Error unmarshal cbor as Identity: %v", err)
	}

	return &topics.Identity, nil
}
