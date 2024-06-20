package exchange_protocol

import (
	"crypto/rand"
	"encoding/base64"
)

const NonceLength = 32

type Nonce []byte

func CreateNonce() (Nonce, error) {
	nonce := make([]byte, NonceLength)
	_, err := rand.Read(nonce)
	if err != nil {
		return nil, err
	}
	return nonce, nil
}

func (n Nonce) String() string {
	return base64.RawURLEncoding.EncodeToString(n)
}
