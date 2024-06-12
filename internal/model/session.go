package model

import (
	"errors"
	"sync"

	"github.com/go-webauthn/webauthn/webauthn"
)

type Sessions struct {
	mu       sync.RWMutex
	sessions map[string]*Session
}

func (s *Sessions) SaveWebauthnSession(typ string, data *webauthn.SessionData) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.sessions[data.Challenge] = &Session{
		id:   data.Challenge,
		typ:  typ,
		data: data,
	}
	return nil
}

func (s *Sessions) GetWebauthnSession(typ, id string) (*webauthn.SessionData, error) {
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
	typ  string
	data *webauthn.SessionData
}
