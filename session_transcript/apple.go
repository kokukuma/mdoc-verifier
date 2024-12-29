package session_transcript

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

const APPLE_HANDOVER_V1 = "AppleIdentityPresentment_1.0"

func AppleHandoverV1(merchantID, temaID string, nonce, requesterIdHash []byte) ([]byte, error) {
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
