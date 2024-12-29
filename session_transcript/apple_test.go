package session_transcript

import (
	"bytes"
	"testing"
)

func TestAppleHandoverV1(t *testing.T) {
	merchantID := "merchant123"
	temaID := "tema123"
	nonce := []byte("testnonce")
	requesterIdHash := []byte("requesterIdHash")

	expectedOutput := []byte{} // Expected CBOR encoded output

	transcript, err := AppleHandoverV1(merchantID, temaID, nonce, requesterIdHash)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(transcript, expectedOutput) {
		t.Errorf("expected %v, got %v", expectedOutput, transcript)
	}
}
