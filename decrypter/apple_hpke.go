package decrypter

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
	hasher := sha256.New()
	hasher.Write(message)
	return hasher.Sum(nil)
}

func AppleHPKE(
	data []byte,
	privateKey *ecdh.PrivateKey,
	sessTrans []byte,
) (*mdoc.DeviceResponse, error) {
	var claims HPKEEnvelope
	if err := cbor.Unmarshal(data, &claims); err != nil {
		return nil, fmt.Errorf("Error unmarshal cbor as HPKEEnvelope: %v", err)
	}

	if !bytes.Equal(digest(sessTrans), claims.Params.InfoHash) {
		return nil, fmt.Errorf("infoHash is not match: %v != %v", digest(sessTrans), claims.Params.InfoHash)
	}

	if !bytes.Equal(digest(privateKey.PublicKey().Bytes()), claims.Params.PkRHash) {
		return nil, fmt.Errorf("PkRHash is not match")
	}

	plaintext, err := DecryptHPKE(claims.Data, claims.Params.PkEM, sessTrans, privateKey)
	if err != nil {
		return nil, fmt.Errorf("Error DecryptHPKE: %v", err)
	}

	topics := struct {
		Identity *mdoc.DeviceResponse `json:"identity"`
	}{}
	if err := cbor.Unmarshal(plaintext, &topics); err != nil {
		return nil, fmt.Errorf("Error unmarshal cbor string: %v", err)
	}
	return topics.Identity, nil
}
