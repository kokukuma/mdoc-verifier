package preview_hpke

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

const BROWSER_HANDOVER_V1 = "BrowserHandoverv1"

type OriginInfo struct {
	Cat     int     `json:"cat"`
	Type    int     `json:"type"`
	Details Details `json:"details"`
}

type Details struct {
	BaseURL string `json:"baseUrl"`
}

func generateBrowserSessionTranscript(nonce []byte, origin string, requesterIdHash []byte) ([]byte, error) {
	originInfo := OriginInfo{
		Cat:  1,
		Type: 1,
		Details: Details{
			BaseURL: origin,
		},
	}
	originInfoBytes, err := cbor.Marshal(originInfo)
	if err != nil {
		return nil, fmt.Errorf("error encoding origin info: %v", err)
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
		return nil, fmt.Errorf("error encoding transcript: %v", err)
	}

	return transcript, nil
}

const ANDROID_HANDOVER_V1 = "AndroidHandoverv1"

func generateAndroidSessionTranscript(nonce []byte, packageName string, requesterIdHash []byte) ([]byte, error) {
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
