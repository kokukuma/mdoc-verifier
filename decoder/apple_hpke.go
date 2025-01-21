package decoder

import (
	"bytes"
	"crypto/ecdh"
	"crypto/sha256"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/kokukuma/mdoc-verifier/mdoc"
)

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

func digest(message []byte) []byte {
	if len(message) == 0 {
		return nil
	}
	h := sha256.New()
	h.Write(message)
	return h.Sum(nil)
}

func AppleHPKE(
	data []byte,
	privateKey *ecdh.PrivateKey,
	sessTrans []byte,
) (*mdoc.DeviceResponse, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty data")
	}
	if privateKey == nil {
		return nil, fmt.Errorf("private key must not be nil")
	}
	if len(sessTrans) == 0 {
		return nil, fmt.Errorf("empty session transcript")
	}

	var claims HPKEEnvelope
	if err := cbor.Unmarshal(data, &claims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal CBOR envelope: %w", err)
	}

	sessHash := digest(sessTrans)
	if !bytes.Equal(sessHash, claims.Params.InfoHash) {
		return nil, fmt.Errorf("session transcript hash mismatch: expected %x, got %x",
			claims.Params.InfoHash, sessHash)
	}

	pkHash := digest(privateKey.PublicKey().Bytes())
	if !bytes.Equal(pkHash, claims.Params.PkRHash) {
		return nil, fmt.Errorf("public key hash mismatch: expected %x, got %x",
			claims.Params.PkRHash, pkHash)
	}

	plaintext, err := DecryptHPKE(claims.Data, claims.Params.PkEM, sessTrans, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt HPKE data: %w", err)
	}

	topics := struct {
		Identity *mdoc.DeviceResponse `json:"identity"`
	}{}
	if err := cbor.Unmarshal(plaintext, &topics); err != nil {
		return nil, fmt.Errorf("failed to unmarshal device response: %w", err)
	}
	if topics.Identity == nil {
		return nil, fmt.Errorf("missing identity in response")
	}
	return topics.Identity, nil
}
