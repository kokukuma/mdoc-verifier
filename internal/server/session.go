package server

import (
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"

	"github.com/google/uuid"
	"github.com/kokukuma/mdoc-verifier/pkg/pki"
)

type Sessions struct {
	mu       sync.RWMutex
	sessions map[string]*Session
}

func (s *Sessions) SaveSession(data *Session) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	data.ID = uuid.New().String()
	s.sessions[data.ID] = data

	return data.ID, nil
}

func (s *Sessions) NewSession(privKeyPath string) (*Session, error) {
	session, err := NewSession(privKeyPath)
	if err != nil {
		return nil, err
	}
	if _, err := s.SaveSession(session); err != nil {
		return nil, err
	}
	return session, nil
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

func (s *Sessions) GetIdentitySession(id string) (*Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.sessions[id]
	if !ok {
		return nil, errors.New("session not found")
	}
	return session, nil
}

func NewSessions() *Sessions {
	return &Sessions{
		sessions: make(map[string]*Session),
	}
}

type Session struct {
	ID             string
	Nonce          Nonce
	PrivateKey     *ecdh.PrivateKey
	VerifyResponse *VerifyResponse
}

func (s *Session) GetNonceByte() []byte {
	return []byte(s.Nonce)
}

func NewSession(privKeyPath string) (*Session, error) {
	nonce, err := CreateNonce()
	if err != nil {
		return nil, err
	}

	// mainly for apple
	if privKeyPath != "" {
		privKey, err := pki.LoadPrivateKey(privKeyPath)
		if err != nil {
			return nil, err
		}
		return &Session{
			Nonce:      nonce,
			PrivateKey: privKey,
		}, nil
	}

	curve := ecdh.P256()
	privKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generateKey: %v", err)
	}
	return &Session{
		Nonce:      nonce,
		PrivateKey: privKey,
	}, nil
}

func (s *Session) GetPrivateKey() *ecdh.PrivateKey {
	return s.PrivateKey
}
