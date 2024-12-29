package session_transcript

import (
	"bytes"
	"testing"
)

func TestBrowserHandoverV1(t *testing.T) {
	nonce := []byte("testnonce")
	origin := "https://example.com"
	requesterIdHash := []byte("requesterIdHash")

	expectedOutput := []byte{} // Expected CBOR encoded output

	transcript, err := BrowserHandoverV1(nonce, origin, requesterIdHash)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(transcript, expectedOutput) {
		t.Errorf("expected %v, got %v", expectedOutput, transcript)
	}
}
