package server

import (
	"errors"
	"sync"

	"github.com/google/uuid"
	"github.com/kokukuma/identity-credential-api-demo/protocol"
)

type Sessions struct {
	mu       sync.RWMutex
	sessions map[string]*Session
}

func (s *Sessions) SaveIdentitySession(data *protocol.SessionData) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	id := uuid.New().String()

	s.sessions[id] = &Session{
		id:   id,
		data: data,
	}
	return id, nil
}

func (s *Sessions) GetIdentitySession(id string) (*protocol.SessionData, error) {
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
	id   string
	data *protocol.SessionData
}
