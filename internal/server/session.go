package server

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"

	"github.com/google/uuid"
	"github.com/kokukuma/mdoc-verifier/document"
	"github.com/kokukuma/mdoc-verifier/pkg/pki"
)

type Sessions struct {
	mu       sync.RWMutex
	sessions map[string]*Session
}

func (s *Sessions) save(data *Session) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	data.ID = uuid.New().String()
	s.sessions[data.ID] = data

	return data.ID, nil
}

func (s *Sessions) NewSession(privKeyPath string, credReq *document.CredentialRequirement) (*Session, error) {
	session, err := newSession(privKeyPath, credReq)
	if err != nil {
		return nil, err
	}
	if _, err := s.save(session); err != nil {
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

func (s *Sessions) GetSession(id string) (*Session, error) {
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
	ID                    string
	Nonce                 Nonce
	PrivateKey            *ecdh.PrivateKey
	VerifyResponse        *VerifyResponse
	CredentialRequirement *document.CredentialRequirement
}

func (s *Session) GetNonceByte() []byte {
	return []byte(s.Nonce)
}

func (s *Session) GetPrivateKey() *ecdh.PrivateKey {
	return s.PrivateKey
}

func (s *Session) GetPublicKeyHash() []byte {
	hash := sha256.Sum256(s.PrivateKey.PublicKey().Bytes())
	return hash[:]
}

func newSession(privKeyPath string, credReq *document.CredentialRequirement) (*Session, error) {
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
			Nonce:                 nonce,
			PrivateKey:            privKey,
			CredentialRequirement: credReq,
		}, nil
	}

	curve := ecdh.P256()
	privKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generateKey: %v", err)
	}
	return &Session{
		Nonce:                 nonce,
		PrivateKey:            privKey,
		CredentialRequirement: credReq,
	}, nil
}
