// Package policy is NIA's client for the policy engine: Tessera, backed
// by OpenFGA. It is deliberately thin. NIA does not reimplement
// relationship-based authorization, Tessera already does that; this
// package defines the interface NIA's control plane and gateway need
// against it, shaped to match Tessera's own public surface so a real
// HTTP adapter is a drop-in once Tessera's v1.2 HTTP surface exists
// (see docs/ARCHITECTURE.md, "Integration plan for Tessera").
//
// Until that surface exists, Client is satisfied by the in-memory
// reference implementation in this package, the same "runs out of the
// box, swap in the real thing later" choice Tessera itself makes for
// IAuthorizationStore and IClientRegistry.
package policy

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Grant mirrors Tessera's Grant record: either a whole api_group, or a
// single method+path endpoint. NIA extends the concept to tools and data
// resources by treating a tool or data resource as just another object a
// grant can name; the wire shape stays the same.
type Grant struct {
	Kind   string // "api_group" | "endpoint" | "tool" | "data"
	Group  string // set when Kind == "api_group"
	Method string // set when Kind == "endpoint"
	Path   string // set when Kind == "endpoint"
	Object string // set when Kind == "tool" or "data"
}

func GrantForAPIGroup(group string) Grant { return Grant{Kind: "api_group", Group: group} }
func GrantForEndpoint(method, path string) Grant {
	return Grant{Kind: "endpoint", Method: method, Path: path}
}
func GrantForTool(tool string) Grant     { return Grant{Kind: "tool", Object: tool} }
func GrantForData(resource string) Grant { return Grant{Kind: "data", Object: resource} }

// KillResult mirrors Tessera's KillResult: what a kill actually did.
type KillResult struct {
	AgentRef      string
	TuplesDeleted int
}

// ErrKilled is returned by any mutating call against an agent that is
// currently killed. Reconciliation must never resurrect a kill; this
// error is how the in-memory reference implementation enforces that
// invariant, matching Tessera's "reconciliation never resurrects a kill."
var ErrKilled = errors.New("policy: agent is killed, restore before mutating grants")

// Client is what NIA's control plane and gateway need from the policy
// engine. Every method here has a direct counterpart in Tessera:
// WriteGrants/DeleteGrants -> IAuthorizationStore.Write/DeleteTuplesAsync,
// Check -> IAuthorizationStore.CheckAsync, Kill/Restore ->
// KillSwitchService, ListGrants -> IAuthorizationStore.ReadTuplesForClientAsync.
type Client interface {
	// WriteGrants declares grants for an agent. Implementations must
	// diff against existing state and only write what's missing,
	// Tessera's idempotent reconcile pattern, because a real OpenFGA
	// write is not itself idempotent.
	WriteGrants(ctx context.Context, agentRef string, grants []Grant) error

	// DeleteGrants removes specific grants without touching the rest.
	DeleteGrants(ctx context.Context, agentRef string, grants []Grant) error

	// ListGrants returns everything currently granted to an agent.
	ListGrants(ctx context.Context, agentRef string) ([]Grant, error)

	// Check asks whether agentRef may exercise the given grant right
	// now. This is the hot-path call the gateway makes on every
	// request; implementations must not cache the result.
	Check(ctx context.Context, agentRef string, grant Grant) (bool, error)

	// Kill sets a durable sentinel and deletes every tuple for
	// agentRef. Sentinel-first, same as Tessera: the sentinel is what
	// makes a kill safe against a concurrent grant landing mid-kill.
	Kill(ctx context.Context, agentRef, incident, operator string) (KillResult, error)

	// Restore clears the kill sentinel and re-declares grants from
	// intent. It does not resurrect grants on its own; the caller
	// must call WriteGrants afterward with the intended state.
	Restore(ctx context.Context, agentRef string) error

	// IsKilled reports whether agentRef currently has a kill sentinel
	// set.
	IsKilled(ctx context.Context, agentRef string) (bool, error)
}

// InMemoryClient is the reference implementation: no OpenFGA, no
// Tessera, just enough state to exercise the interface and to develop
// against locally. It enforces the same invariants Tessera enforces
// (sentinel-first kill, no resurrection on write, per-agent mutual
// exclusion via the mutex) so code written against this can be pointed
// at the real Tessera HTTP client later without surprises.
type InMemoryClient struct {
	mu     sync.Mutex
	grants map[string][]Grant
	killed map[string]killRecord
}

type killRecord struct {
	incident string
	operator string
	at       time.Time
}

func NewInMemoryClient() *InMemoryClient {
	return &InMemoryClient{
		grants: make(map[string][]Grant),
		killed: make(map[string]killRecord),
	}
}

func (c *InMemoryClient) WriteGrants(_ context.Context, agentRef string, grants []Grant) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, dead := c.killed[agentRef]; dead {
		return fmt.Errorf("%w: %s", ErrKilled, agentRef)
	}
	existing := c.grants[agentRef]
	for _, g := range grants {
		if !containsGrant(existing, g) {
			existing = append(existing, g)
		}
	}
	c.grants[agentRef] = existing
	return nil
}

func (c *InMemoryClient) DeleteGrants(_ context.Context, agentRef string, grants []Grant) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	existing := c.grants[agentRef]
	kept := existing[:0]
	for _, g := range existing {
		if !containsGrant(grants, g) {
			kept = append(kept, g)
		}
	}
	c.grants[agentRef] = kept
	return nil
}

func (c *InMemoryClient) ListGrants(_ context.Context, agentRef string) ([]Grant, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Grant, len(c.grants[agentRef]))
	copy(out, c.grants[agentRef])
	return out, nil
}

func (c *InMemoryClient) Check(_ context.Context, agentRef string, grant Grant) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, dead := c.killed[agentRef]; dead {
		return false, nil
	}
	return containsGrant(c.grants[agentRef], grant), nil
}

func (c *InMemoryClient) Kill(_ context.Context, agentRef, incident, operator string) (KillResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.killed[agentRef] = killRecord{incident: incident, operator: operator, at: time.Now()}
	deleted := len(c.grants[agentRef])
	c.grants[agentRef] = nil
	return KillResult{AgentRef: agentRef, TuplesDeleted: deleted}, nil
}

func (c *InMemoryClient) Restore(_ context.Context, agentRef string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.killed, agentRef)
	return nil
}

func (c *InMemoryClient) IsKilled(_ context.Context, agentRef string) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, dead := c.killed[agentRef]
	return dead, nil
}

func containsGrant(list []Grant, g Grant) bool {
	for _, x := range list {
		if x == g {
			return true
		}
	}
	return false
}

var _ Client = (*InMemoryClient)(nil)
