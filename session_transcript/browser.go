package session_transcript

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// TODO: session transcript: 9.1.5.1 Session transcript

type OriginInfo struct {
	Cat     int     `json:"cat"`
	Type    int     `json:"type"`
	Details Details `json:"details"`
}

type Details struct {
	BaseURL string `json:"baseUrl"`
}

const BROWSER_HANDOVER_V1 = "BrowserHandoverv1"

func BrowserHandoverV1(nonce []byte, origin string, requesterIdHash []byte) ([]byte, error) {
	// Input validation
	if len(nonce) == 0 {
		return nil, fmt.Errorf("nonce cannot be empty")
	}
	if origin == "" {
		return nil, fmt.Errorf("origin cannot be empty")
	}
	if len(requesterIdHash) == 0 {
		return nil, fmt.Errorf("requesterIdHash cannot be empty")
	}

	originInfo := OriginInfo{
		Cat:  1,
		Type: 1,
		Details: Details{
			BaseURL: origin,
		},
	}
	originInfoBytes, err := cbor.Marshal(originInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to encode origin info: %w", err)
	}

	// Create the final CBOR array
	browserHandover := []interface{}{
		nil, // DeviceEngagementBytes
		nil, // EReaderKeyBytes
		[]interface{}{ // BrowserHandover
			BROWSER_HANDOVER_V1,
			nonce,
			originInfoBytes,
			requesterIdHash,
		},
	}

	transcript, err := cbor.Marshal(browserHandover)
	if err != nil {
		return nil, fmt.Errorf("failed to encode session transcript: %w", err)
	}

	return transcript, nil
}
