package server

import (
	"crypto/ecdh"
	"errors"
	"sync"

	"github.com/google/uuid"
)

type Sessions struct {
	mu       sync.RWMutex
	sessions map[string]*Session
}

// TODO: Sessionは全部こっち側に持ってくる

func (s *Sessions) SaveIdentitySession(data *SessionData) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	id := uuid.New().String()

	s.sessions[id] = &Session{
		id:   id,
		data: data,
	}
	return id, nil
}

func (s *Sessions) AddVerifyResponse(id string, vr VerifyResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.sessions[id].VerifyResponse = &vr
	return nil
}
func (s *Sessions) GetVerifyResponse(id string) (*VerifyResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.sessions[id]
	if !ok {
		return nil, errors.New("session not found")
	}
	return session.VerifyResponse, nil
}

func (s *Sessions) GetIdentitySession(id string) (*SessionData, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.sessions[id]
	if !ok {
		return nil, errors.New("session not found")
	}
	return session.data, nil
}

func NewSessions() *Sessions {
	return &Sessions{
		sessions: make(map[string]*Session),
	}
}

type Session struct {
	id             string
	data           *SessionData
	VerifyResponse *VerifyResponse
}

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
