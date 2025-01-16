package session_transcript

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

const ANDROID_HANDOVER_V1 = "AndroidHandoverv1"

func AndroidHandoverV1(nonce []byte, packageName string, requesterIdHash []byte) ([]byte, error) {
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
		return nil, fmt.Errorf("error encoding transcript: %v", err)
	}

	return transcript, nil
}
