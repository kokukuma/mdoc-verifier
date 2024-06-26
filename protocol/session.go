package protocol

import (
	"crypto/ecdh"
)

type SessionData struct {
	Nonce      Nonce            `json:"challenge"`
	PrivateKey *ecdh.PrivateKey `json:"private_key"`
}

func (s *SessionData) GetNonceByte() []byte {
	return []byte(s.Nonce)
}

func (s *SessionData) GetPrivateKey() *ecdh.PrivateKey {
	return s.PrivateKey
}
