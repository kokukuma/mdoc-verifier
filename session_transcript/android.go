package session_transcript

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

const ANDROID_HANDOVER_V1 = "AndroidHandoverv1"

func AndroidHandoverV1(nonce []byte, packageName string, requesterIdHash []byte) ([]byte, error) {
	// Input validation
	if len(nonce) == 0 {
		return nil, fmt.Errorf("nonce cannot be empty")
	}
	if packageName == "" {
		return nil, fmt.Errorf("packageName cannot be empty")
	}
	if len(requesterIdHash) == 0 {
		return nil, fmt.Errorf("requesterIdHash cannot be empty")
	}
	// Create the AndroidHandover array
	androidHandover := []interface{}{
		ANDROID_HANDOVER_V1,
		nonce,
		[]byte(packageName),
		requesterIdHash,
	}

	// Create the final CBOR array
	sessionTranscript := []interface{}{
		nil, // DeviceEngagementBytes
		nil, // EReaderKeyBytes
		androidHandover,
	}

	transcript, err := cbor.Marshal(sessionTranscript)
	if err != nil {
		return nil, fmt.Errorf("failed to encode session transcript: %w", err)
	}

	return transcript, nil
}
