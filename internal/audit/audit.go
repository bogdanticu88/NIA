// Package audit is NIA's append-only audit trail. It aggregates events
// from three sources: the control plane (registration, credential,
// permission changes), the gateway (every authorization decision), and
// Tessera itself (kill/restore events, once the HTTP bridge exists,
// see internal/policy). One event shape, one sink, so an incident
// review is one query instead of three.
package audit

import (
	"context"
	"sync"
	"time"
)

// Event is one audit entry. Action is a short verb.namespace string, e.g.
// "agent.registered", "grant.written", "gateway.denied", "policy.killed".
// AgentRef is the subject the event is about, Operator is who or what
// caused it (a human operator, "system", or another AgentRef for
// agent-initiated actions like delegation).
type Event struct {
	Action   string
	AgentRef string
	Operator string
	Incident string // set for kill/restore and other incident-linked events
	Detail   string // short free-text, e.g. the grant or endpoint involved
	At       time.Time
}

// Sink is an append-only audit destination. Matches Tessera's
// IAuditSink shape (see Tessera.ControlPlane/Abstractions.cs) so events
// forwarded from Tessera don't need translation beyond field names.
// The gateway only ever writes, so it depends on Sink rather than the
// wider Store, one place appending events can't accidentally start
// reading them back.
type Sink interface {
	Append(ctx context.Context, evt Event) error
}

// Store is a Sink that can also be queried. cmd/api holds one of these,
// not a bare Sink, because the audit endpoints (recent events, an
// agent's history) need to read the same trail back regardless of which
// backend is behind it. Both methods take ctx and return an error, even
// though InMemorySink below never fails, because the real backend this
// is written against (Postgres, see the roadmap note at the bottom of
// this file) very much can.
type Store interface {
	Sink
	// Recent returns up to n most recent events, oldest first. n <= 0
	// or n greater than what's available returns everything there is.
	Recent(ctx context.Context, n int) ([]Event, error)
	// ForAgent returns every recorded event for a given agent, oldest
	// first. This is the query an incident review starts with.
	ForAgent(ctx context.Context, agentRef string) ([]Event, error)
}

// InMemorySink keeps the last N events in memory. Useful for local dev
// and tests; a production deployment points this interface at a real
// store (Postgres, a SIEM forwarder) instead.
type InMemorySink struct {
	mu     sync.Mutex
	events []Event
	max    int
}

func NewInMemorySink(max int) *InMemorySink {
	if max <= 0 {
		max = 10_000
	}
	return &InMemorySink{max: max}
}

func (s *InMemorySink) Append(_ context.Context, evt Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if evt.At.IsZero() {
		evt.At = time.Now()
	}
	s.events = append(s.events, evt)
	if len(s.events) > s.max {
		s.events = s.events[len(s.events)-s.max:]
	}
	return nil
}

// Recent returns up to n most recent events, oldest first. Never
// returns an error, it's in-memory; the signature matches Store because
// callers write against the interface, not this concrete type.
func (s *InMemorySink) Recent(_ context.Context, n int) ([]Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n <= 0 || n > len(s.events) {
		n = len(s.events)
	}
	out := make([]Event, n)
	copy(out, s.events[len(s.events)-n:])
	return out, nil
}

// ForAgent returns every recorded event for a given agent, in order.
// This is the query an incident review starts with.
func (s *InMemorySink) ForAgent(_ context.Context, agentRef string) ([]Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Event
	for _, e := range s.events {
		if e.AgentRef == agentRef {
			out = append(out, e)
		}
	}
	return out, nil
}

var (
	_ Sink  = (*InMemorySink)(nil)
	_ Store = (*InMemorySink)(nil)
)

// Not yet real: this package still has exactly one implementation, and
// it forgets everything on restart and can't be shared across the
// nia-api and nia-gateway processes that both want to write to it, so
// "one stream" in the package doc above is aspirational until a
// Postgres-backed Store exists. That's the next piece of work, not
// started here, see docs/ARCHITECTURE.md's audit trail row.
