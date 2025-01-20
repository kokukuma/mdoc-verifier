package session_transcript

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

const APPLE_HANDOVER_V1 = "AppleIdentityPresentment_1.0"

func AppleHandoverV1(merchantID, teamID string, nonce, requesterIdHash []byte) ([]byte, error) {
	// Input validation
	if merchantID == "" {
		return nil, fmt.Errorf("merchantID cannot be empty")
	}
	if teamID == "" {
		return nil, fmt.Errorf("teamID cannot be empty")
	}
	if len(nonce) == 0 {
		return nil, fmt.Errorf("nonce cannot be empty")
	}
	if len(requesterIdHash) == 0 {
		return nil, fmt.Errorf("requesterIdHash cannot be empty")
	}

	// Create the final CBOR array
	appleHandover := []interface{}{
		nil, // DeviceEngagementBytes
		nil, // EReaderKeyBytes
		[]interface{}{ // AppleHandover
			APPLE_HANDOVER_V1,
			nonce,
			merchantID,
			teamID,
			requesterIdHash,
		},
	}

	transcript, err := cbor.Marshal(appleHandover)
	if err != nil {
		return nil, fmt.Errorf("failed to encode session transcript: %w", err)
	}

	return transcript, nil
}
