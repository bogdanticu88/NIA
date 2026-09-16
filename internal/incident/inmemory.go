package incident

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
)

// InMemoryStore is the reference Store implementation, the same shape
// as every other in-memory store in this codebase: a process-local map,
// good enough for local dev and for a single gateway instance, not
// shared across replicas, no persistence across a restart. Unlike
// internal/audit, there's no Postgres-backed alternative yet, see this
// package's own doc comment and docs/ARCHITECTURE.md for why that's an
// open gap rather than a hidden one.
type InMemoryStore struct {
	mu    sync.Mutex
	byID  map[string]Incident
	order []string // insertion order, oldest first, so List can return it without sorting
}

func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{byID: make(map[string]Incident)}
}

func (s *InMemoryStore) Create(_ context.Context, in Incident) (Incident, error) {
	id, err := randomID()
	if err != nil {
		return Incident{}, err
	}
	in.ID = id
	s.mu.Lock()
	s.byID[id] = in
	s.order = append(s.order, id)
	s.mu.Unlock()
	return in, nil
}

func (s *InMemoryStore) Get(_ context.Context, id string) (Incident, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	in, ok := s.byID[id]
	if !ok {
		return Incident{}, ErrNotFound
	}
	return in, nil
}

func (s *InMemoryStore) List(_ context.Context, agentRef string, limit int) ([]Incident, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Incident
	for _, id := range s.order {
		in := s.byID[id]
		if agentRef != "" && in.AgentRef != agentRef {
			continue
		}
		out = append(out, in)
	}
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out, nil
}

func randomID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "inc-" + hex.EncodeToString(b), nil
}

var _ Store = (*InMemoryStore)(nil)
