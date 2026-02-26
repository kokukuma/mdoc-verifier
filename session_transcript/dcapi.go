package session_transcript

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/fxamacker/cbor/v2"
)

var (
	b64 = base64.URLEncoding.WithPadding(base64.NoPadding)
)

const DCAPI_HANDOVER = "dcapi"

// DcapiHandover creates a session transcript for the DC API (org-iso-mdoc) protocol.
// This follows ISO/IEC 18013-7 Annex C specification.
//
// The session transcript structure is:
// SessionTranscript = [null, null, ["dcapi", SHA256(dcapiInfo)]]
//
// Where dcapiInfo = [base64url(encryptionInfo), origin]
func DcapiHandover(encryptionInfo []byte, origin string) ([]byte, error) {
	// Input validation
	if len(encryptionInfo) == 0 {
		return nil, fmt.Errorf("encryptionInfo cannot be empty")
	}
	if origin == "" {
		return nil, fmt.Errorf("origin cannot be empty")
	}

	// Create dcapiInfo: [base64url(encryptionInfo), origin]
	encryptionInfoB64 := b64.EncodeToString(encryptionInfo)
	dcapiInfo := []interface{}{
		encryptionInfoB64,
		origin,
	}

	// Encode dcapiInfo as CBOR
	dcapiInfoBytes, err := cbor.Marshal(dcapiInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to encode dcapiInfo: %w", err)
	}

	// Calculate SHA256 hash of dcapiInfo
	dcapiInfoHash := sha256.Sum256(dcapiInfoBytes)

	// Log dcapiInfo for debugging
	log.Printf("DcapiHandover: encryptionInfo (hex): %s", hex.EncodeToString(encryptionInfo))
	log.Printf("DcapiHandover: encryptionInfoB64: %s", encryptionInfoB64)
	log.Printf("DcapiHandover: origin: %s", origin)
	log.Printf("DcapiHandover: dcapiInfoBytes (hex): %s", hex.EncodeToString(dcapiInfoBytes))
	log.Printf("DcapiHandover: dcapiInfoHash (hex): %s", hex.EncodeToString(dcapiInfoHash[:]))

	// Create the dcapi handover array: ["dcapi", SHA256(dcapiInfo)]
	dcapiHandover := []interface{}{
		DCAPI_HANDOVER,
		dcapiInfoHash[:],
	}

	// Create the final CBOR array (SessionTranscript)
	sessionTranscript := []interface{}{
		nil, // DeviceEngagementBytes
		nil, // EReaderKeyBytes
		dcapiHandover,
	}

	transcript, err := cbor.Marshal(sessionTranscript)
	if err != nil {
		return nil, fmt.Errorf("failed to encode session transcript: %w", err)
	}

	return transcript, nil
}
