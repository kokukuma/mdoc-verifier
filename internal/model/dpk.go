package model

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

var (
	ErrNoDevicePubKey = errors.New("no device pub key")
)

type ParsedAttObjForDevicePublicKey struct {
	AAGUID       []byte                 `json:"aaguid"`
	DPK          []byte                 `json:"dpk"`
	Scope        uint                   `json:"scope"`
	Nonce        []byte                 `json:"nonce"`
	Format       string                 `json:"fmt"`
	AttStatement map[string]interface{} `json:"attStmt,omitempty"`
	EPAtt        bool                   `json:"epAtt"`
}

type RawDPK struct {
	devicePubKey  map[string]interface{}
	signatureData []byte
}

func ParseDevicePublicKeyByAttestation(pcc *protocol.ParsedCredentialCreationData) (*ParsedAttObjForDevicePublicKey, error) {
	rdpk, err := rawDPKFromAttestation(pcc)
	if err != nil {
		return nil, err
	}
	return parseDevicePublicKey(rdpk)
}

func ParseDevicePublicKeyByAssertion(pca *protocol.ParsedCredentialAssertionData) (*ParsedAttObjForDevicePublicKey, error) {
	rdpk, err := rawDPKFromAssertion(pca)
	if err != nil {
		return nil, err
	}
	return parseDevicePublicKey(rdpk)
}

func rawDPKFromAttestation(pcc *protocol.ParsedCredentialCreationData) (*RawDPK, error) {
	var devicePubKey map[string]interface{}
	for key, res := range pcc.Raw.ClientExtensionResults {
		if key == "devicePubKey" {
			if _, ok := res.(map[string]interface{}); ok {
				devicePubKey = res.(map[string]interface{})
			}
		}
	}
	if len(devicePubKey) == 0 {
		return nil, ErrNoDevicePubKey
	}
	clientDataHash := sha256.Sum256(pcc.Raw.AttestationResponse.ClientDataJSON)
	signatureData := append(pcc.Response.AttestationObject.RawAuthData, clientDataHash[:]...)
	// pcc.Raw.AttestationResponse.AttestationObject でもいい?

	return &RawDPK{
		devicePubKey:  devicePubKey,
		signatureData: signatureData,
	}, nil
}

func rawDPKFromAssertion(pca *protocol.ParsedCredentialAssertionData) (*RawDPK, error) {
	var devicePubKey map[string]interface{}
	for key, res := range pca.Raw.ClientExtensionResults {
		if key == "devicePubKey" {
			if _, ok := res.(map[string]interface{}); ok {
				devicePubKey = res.(map[string]interface{})
			}
		}
	}
	if len(devicePubKey) == 0 {
		return nil, ErrNoDevicePubKey
	}
	clientDataHash := sha256.Sum256(pca.Raw.AssertionResponse.ClientDataJSON)
	signatureData := append(pca.Raw.AssertionResponse.AuthenticatorData, clientDataHash[:]...)

	return &RawDPK{
		devicePubKey:  devicePubKey,
		signatureData: signatureData,
	}, nil
}

func parseDevicePublicKey(rdpk *RawDPK) (*ParsedAttObjForDevicePublicKey, error) {
	// https://w3c.github.io/webauthn/#sctn-device-publickey-extension-verification-create

	var authenticatorOutput []byte
	var signature []byte
	var err error

	if out := rdpk.devicePubKey["authenticatorOutput"].(string); out != "" {
		authenticatorOutput, err = base64.RawURLEncoding.DecodeString(out)
		if err != nil {
			return nil, err
		}
	}

	if out := rdpk.devicePubKey["signature"].(string); out != "" {
		signature, err = base64.RawURLEncoding.DecodeString(out)
		if err != nil {
			return nil, err
		}
	}
	fmt.Println("-------------------------")
	fmt.Println(authenticatorOutput)
	fmt.Println(signature)

	var p ParsedAttObjForDevicePublicKey
	if err := webauthncbor.Unmarshal(authenticatorOutput, &p); err != nil {
		return nil, err
	}

	key, err := webauthncose.ParsePublicKey(p.DPK)
	if err != nil {
		return nil, err
	}
	fmt.Println("parsed key: ", key)

	valid, err := webauthncose.VerifySignature(key, rdpk.signatureData, signature)
	if !valid || err != nil {
		fmt.Println("failed to validate: ", valid, err)
		return nil, err
	}
	fmt.Println(valid)

	return &p, nil
}
