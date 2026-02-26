package decoder

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"

	"github.com/fxamacker/cbor/v2"
	"github.com/kokukuma/mdoc-verifier/mdoc"
)

var (
	b64 = base64.URLEncoding.WithPadding(base64.StdPadding)
)

// MdocAPIResponse represents the JSON response format for org-iso-mdoc protocol
type MdocAPIResponse struct {
	Response string `json:"response"` // base64url-encoded CBOR
}

// MdocAPIEncryptedResponse represents the CBOR structure of the encrypted response
// Structure: ["dcapi", {"enc": bytes, "cipherText": bytes}]
type MdocAPIEncryptedResponse struct {
	Enc        []byte // Ephemeral public key (pkEm)
	CipherText []byte // Encrypted DeviceResponse
}

// MdocAPI decrypts and decodes a response from the org-iso-mdoc protocol
//
// The response format is:
// - JSON: {"response": "base64url-encoded-cbor"}
// - CBOR: ["dcapi", {"enc": bytes, "cipherText": bytes}]
//
// Parameters:
// - data: The JSON response string from the wallet
// - privateKey: The verifier's private key for HPKE decryption
// - sessTrans: The session transcript (used as HPKE info parameter)
func MdocAPI(
	data string,
	privateKey *ecdh.PrivateKey,
	sessTrans []byte,
) (*mdoc.DeviceResponse, error) {
	if data == "" {
		return nil, fmt.Errorf("empty data")
	}
	if privateKey == nil {
		return nil, fmt.Errorf("private key must not be nil")
	}
	if len(sessTrans) == 0 {
		return nil, fmt.Errorf("session transcript must not be empty")
	}

	// Parse JSON response
	log.Printf("MdocAPI: received data (first 500 chars): %.500s", data)

	var jsonResp MdocAPIResponse
	if err := json.Unmarshal([]byte(data), &jsonResp); err != nil {
		return nil, fmt.Errorf("failed to parse JSON response: %w", err)
	}

	log.Printf("MdocAPI: response field (first 200 chars): %.200s", jsonResp.Response)

	// Decode base64url response
	// Try with NoPadding first as some implementations omit padding
	responseBytes, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(jsonResp.Response)
	if err != nil {
		// Fallback to standard padding
		responseBytes, err = b64.DecodeString(jsonResp.Response)
		if err != nil {
			return nil, fmt.Errorf("failed to decode base64url response: %w", err)
		}
	}

	// Parse CBOR response: ["dcapi", {"enc": bytes, "cipherText": bytes}]
	var cborArray []cbor.RawMessage
	if err := cbor.Unmarshal(responseBytes, &cborArray); err != nil {
		return nil, fmt.Errorf("failed to unmarshal CBOR array: %w", err)
	}

	if len(cborArray) != 2 {
		return nil, fmt.Errorf("expected CBOR array of length 2, got %d", len(cborArray))
	}

	// Verify first element is "dcapi"
	var protocol string
	if err := cbor.Unmarshal(cborArray[0], &protocol); err != nil {
		return nil, fmt.Errorf("failed to unmarshal protocol: %w", err)
	}
	if protocol != "dcapi" {
		return nil, fmt.Errorf("expected 'dcapi' protocol, got '%s'", protocol)
	}

	// Parse encryption parameters map
	var encParams map[string]cbor.RawMessage
	if err := cbor.Unmarshal(cborArray[1], &encParams); err != nil {
		return nil, fmt.Errorf("failed to unmarshal encryption parameters: %w", err)
	}

	// Extract enc and cipherText
	var enc []byte
	var cipherText []byte

	if encBytes, ok := encParams["enc"]; ok {
		if err := cbor.Unmarshal(encBytes, &enc); err != nil {
			return nil, fmt.Errorf("failed to unmarshal enc: %w", err)
		}
	} else {
		return nil, fmt.Errorf("missing 'enc' in encryption parameters")
	}

	if ctBytes, ok := encParams["cipherText"]; ok {
		if err := cbor.Unmarshal(ctBytes, &cipherText); err != nil {
			return nil, fmt.Errorf("failed to unmarshal cipherText: %w", err)
		}
	} else {
		return nil, fmt.Errorf("missing 'cipherText' in encryption parameters")
	}

	// Decrypt using HPKE
	// info = sessionTranscript
	// encapsulatedKey = enc
	// ciphertext = cipherText
	plaintext, err := DecryptHPKE(cipherText, enc, sessTrans, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt HPKE data: %w", err)
	}

	// Parse DeviceResponse
	var devResp *mdoc.DeviceResponse
	if err := cbor.Unmarshal(plaintext, &devResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal DeviceResponse: %w", err)
	}

	return devResp, nil
}
