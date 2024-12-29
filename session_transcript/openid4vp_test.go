package session_transcript

import (
	"bytes"
	"testing"
)

func TestOID4VPHandover(t *testing.T) {
	nonce := []byte("testnonce")
	clientID := "client123"
	responseURI := "https://response.uri"
	apu := "base64encodedapu"

	expectedOutput := []byte{} // Expected CBOR encoded output

	transcript, err := OID4VPHandover(nonce, clientID, responseURI, apu)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(transcript, expectedOutput) {
		t.Errorf("expected %v, got %v", expectedOutput, transcript)
	}
}
