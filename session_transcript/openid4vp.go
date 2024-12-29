package session_transcript

import (
	"encoding/base64"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/kokukuma/mdoc-verifier/pkg/hash"
)

// https://github.com/eu-digital-identity-wallet/eudi-lib-android-wallet-core/blob/327c006eeb256353a8ed064adb12487db1bd352c/wallet-core/src/main/java/eu/europa/ec/eudi/wallet/internal/Openid4VpUtils.kt#L26
func OID4VPHandover(nonce []byte, clientID, responseURI, apu string) ([]byte, error) {

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
