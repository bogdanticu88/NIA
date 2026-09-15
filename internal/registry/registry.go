// Package registry is where non-human identities and the tools they can
// call get onboarded and inventoried. Registration here is deliberately
// separate from granting permissions (internal/policy): registering an
// agent creates the identity record, it does not by itself authorize
// anything. Mirrors Tessera's ClientProvisioner, which onboards a client
// record distinctly from writing its grants.
package registry

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/bogdanticu88/nia/internal/identity"
)

var (
	ErrAlreadyRegistered = errors.New("registry: agent already registered")
	ErrNotFound          = errors.New("registry: agent not found")
)

// AgentRegistry is the NHI inventory: registration, lookup, and listing.
type AgentRegistry interface {
	Register(ctx context.Context, agent identity.AgentRef) error
	Get(ctx context.Context, ref string) (identity.AgentRef, error)
	List(ctx context.Context) ([]identity.AgentRef, error)
	// SetState updates lifecycle state. The kill switch itself lives in
	// internal/policy (it deletes OpenFGA tuples); this only reflects
	// the resulting state on the identity record so inventory queries
	// stay accurate without hitting the policy client.
	SetState(ctx context.Context, ref string, state identity.LifecycleState) error
}

// InMemoryAgentRegistry is the reference implementation.
type InMemoryAgentRegistry struct {
	mu     sync.Mutex
	agents map[string]identity.AgentRef
}

func NewInMemoryAgentRegistry() *InMemoryAgentRegistry {
	return &InMemoryAgentRegistry{agents: make(map[string]identity.AgentRef)}
}

func (r *InMemoryAgentRegistry) Register(_ context.Context, agent identity.AgentRef) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.agents[agent.Ref]; exists {
		return ErrAlreadyRegistered
	}
	if agent.RegisteredAt.IsZero() {
		agent.RegisteredAt = time.Now()
	}
	if agent.State == "" {
		agent.State = identity.StateActive
	}
	r.agents[agent.Ref] = agent
	return nil
}

func (r *InMemoryAgentRegistry) Get(_ context.Context, ref string) (identity.AgentRef, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.agents[ref]
	if !ok {
		return identity.AgentRef{}, ErrNotFound
	}
	return a, nil
}

func (r *InMemoryAgentRegistry) List(_ context.Context) ([]identity.AgentRef, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]identity.AgentRef, 0, len(r.agents))
	for _, a := range r.agents {
		out = append(out, a)
	}
	return out, nil
}

func (r *InMemoryAgentRegistry) SetState(_ context.Context, ref string, state identity.LifecycleState) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.agents[ref]
	if !ok {
		return ErrNotFound
	}
	a.State = state
	if state == identity.StateKilled {
		now := time.Now()
		a.KilledAt = &now
	}
	r.agents[ref] = a
	return nil
}

var _ AgentRegistry = (*InMemoryAgentRegistry)(nil)
