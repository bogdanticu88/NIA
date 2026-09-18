package credentials

import (
	"context"
	"sync"
	"time"
)

// InMemoryStore is the reference Store implementation. Every method
// below runs under a single mutex, which is what makes Rotate's
// revoke-then-issue actually atomic: no Verify or second Rotate call
// against the same row can observe a half-finished rotation.
type InMemoryStore struct {
	mu   sync.Mutex
	byID map[string]Credential
}

func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{byID: make(map[string]Credential)}
}

func (s *InMemoryStore) Issue(_ context.Context, agentRef string, kind Kind, ttl time.Duration) (Credential, string, error) {
	id, err := randomID()
	if err != nil {
		return Credential{}, "", err
	}
	secret, digest, err := newSecret()
	if err != nil {
		return Credential{}, "", err
	}
	now := time.Now()
	cred := Credential{
		ID:         id,
		AgentRef:   agentRef,
		Kind:       kind,
		Status:     StatusActive,
		SecretHash: digest,
		IssuedAt:   now,
	}
	if ttl > 0 {
		exp := now.Add(ttl)
		cred.ExpiresAt = &exp
	}
	s.mu.Lock()
	s.byID[id] = cred
	s.mu.Unlock()
	return cred, secret, nil
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

func (s *InMemoryStore) Disable(_ context.Context, id, disabledBy, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.byID[id]
	if !ok {
		return ErrNotFound
	}
	now := time.Now()
	c.Status = StatusDisabled
	c.DisabledAt = &now
	c.DisabledBy = disabledBy
	c.Reason = reason
	c.EnabledAt = nil
	s.byID[id] = c
	return nil
}

func (s *InMemoryStore) Enable(_ context.Context, id, enabledBy string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.byID[id]
	if !ok {
		return ErrNotFound
	}
	if c.Status == StatusRevoked {
		// Revoked is one-way, Enable on a revoked credential is a
		// no-op-that-errors rather than quietly resurrecting a
		// credential a security decision already retired. A new
		// credential is the right answer, not un-revoking this one.
		return ErrInvalidCredential
	}
	now := time.Now()
	c.Status = StatusActive
	c.EnabledAt = &now
	c.DisabledAt = nil
	c.DisabledBy = ""
	s.byID[id] = c
	return nil
}

func (s *InMemoryStore) Rotate(_ context.Context, id, rotatedBy string, ttl time.Duration) (Credential, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	old, ok := s.byID[id]
	if !ok {
		return Credential{}, "", ErrNotFound
	}

	newID, err := randomID()
	if err != nil {
		return Credential{}, "", err
	}
	secret, digest, err := newSecret()
	if err != nil {
		return Credential{}, "", err
	}
	now := time.Now()

	old.Status = StatusRevoked
	old.RevokedAt = &now
	old.RevokedBy = rotatedBy
	old.Reason = "rotated, superseded by " + newID
	old.RotatedTo = newID

	next := Credential{
		ID:          newID,
		AgentRef:    old.AgentRef,
		Kind:        old.Kind,
		Status:      StatusActive,
		SecretHash:  digest,
		IssuedAt:    now,
		RotatedFrom: id,
	}
	if ttl > 0 {
		exp := now.Add(ttl)
		next.ExpiresAt = &exp
	}

	// Both writes land before either is observable from outside this
	// critical section: no Verify call anywhere can see the old
	// credential already revoked while the new one doesn't exist yet,
	// or the new one active while the old one is still valid.
	s.byID[id] = old
	s.byID[newID] = next
	return next, secret, nil
}

func (s *InMemoryStore) Verify(_ context.Context, id, presentedSecret string) (Credential, error) {
	s.mu.Lock()
	c, ok := s.byID[id]
	s.mu.Unlock()
	// Deliberately no early return on !ok, see verifyPresented.
	return verifyPresented(c, ok, presentedSecret, time.Now())
}

var _ Store = (*InMemoryStore)(nil)
