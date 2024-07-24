package openid4vp

import (
	"encoding/base64"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/kokukuma/mdoc-verifier/pkg/hash"
)

// TODO: session transcript: 9.1.5.1 Session transcript

const BROWSER_HANDOVER_V1 = "BrowserHandoverv1"

type OriginInfo struct {
	Cat     int     `json:"cat"`
	Type    int     `json:"type"`
	Details Details `json:"details"`
}

type Details struct {
	BaseURL string `json:"baseUrl"`
}

func SessionTranscriptBrowser(nonce []byte, origin string, requesterIdHash []byte) ([]byte, error) {
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

// https://github.com/eu-digital-identity-wallet/eudi-lib-android-wallet-core/blob/327c006eeb256353a8ed064adb12487db1bd352c/wallet-core/src/main/java/eu/europa/ec/eudi/wallet/internal/Openid4VpUtils.kt#L26
func SessionTranscriptOID4VP(nonce []byte, clientID, responseURI, apu string) ([]byte, error) {

	// nonce and mdocGeneratedNonce must be treated as tstr
	nonceStr := string(nonce)

	// It have to be nopadding
	mdocGeneratedNonce, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(apu)
	if err != nil {
		return nil, fmt.Errorf("failed to decode mdocGeneratedNonce")
	}
	mdocGeneratedNonceStr := string(mdocGeneratedNonce)

	clientIdToHash, err := cbor.Marshal([]interface{}{clientID, mdocGeneratedNonceStr})
	if err != nil {
		return nil, err
	}

	responseUriToHash, err := cbor.Marshal([]interface{}{responseURI, mdocGeneratedNonceStr})
	if err != nil {
		return nil, err
	}
	clientIdHash := hash.Digest(clientIdToHash, "SHA-256")
	responseURIHash := hash.Digest(responseUriToHash, "SHA-256")

	// Create the final CBOR array
	oid4vpHandover := []interface{}{
		nil, // DeviceEngagementBytes
		nil, // EReaderKeyBytes
		[]interface{}{ // OID4VPHandover
			clientIdHash,
			responseURIHash,
			nonceStr,
		},
	}

	transcript, err := cbor.Marshal(oid4vpHandover)
	if err != nil {
		return nil, fmt.Errorf("error encoding transcript: %v", err)
	}

	return transcript, nil
}
