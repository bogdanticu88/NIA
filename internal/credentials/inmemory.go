package credentials

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// InMemoryStore is the reference Store implementation.
type InMemoryStore struct {
	mu   sync.Mutex
	byID map[string]Credential
}

func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{byID: make(map[string]Credential)}
}

func (s *InMemoryStore) Issue(_ context.Context, agentRef string, kind Kind, ttl time.Duration) (Credential, error) {
	id, err := randomID()
	if err != nil {
		return Credential{}, err
	}
	now := time.Now()
	cred := Credential{
		ID:       id,
		AgentRef: agentRef,
		Kind:     kind,
		Status:   StatusActive,
		IssuedAt: now,
	}
	if ttl > 0 {
		exp := now.Add(ttl)
		cred.ExpiresAt = &exp
	}
	s.mu.Lock()
	s.byID[id] = cred
	s.mu.Unlock()
	return cred, nil
}

func (s *InMemoryStore) Get(_ context.Context, id string) (Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.byID[id]
	if !ok {
		return Credential{}, ErrNotFound
	}
	return c, nil
}

func (s *InMemoryStore) ListForAgent(_ context.Context, agentRef string) ([]Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Credential
	for _, c := range s.byID {
		if c.AgentRef == agentRef {
			out = append(out, c)
		}
	}
	return out, nil
}

func (s *InMemoryStore) Revoke(_ context.Context, id, revokedBy, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.byID[id]
	if !ok {
		return ErrNotFound
	}
	now := time.Now()
	c.Status = StatusRevoked
	c.RevokedAt = &now
	c.RevokedBy = revokedBy
	c.Reason = reason
	s.byID[id] = c
	return nil
}

func randomID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

var _ Store = (*InMemoryStore)(nil)
