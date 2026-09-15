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
type Sink interface {
	Append(ctx context.Context, evt Event) error
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

// Recent returns up to n most recent events, newest last.
func (s *InMemorySink) Recent(n int) []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n <= 0 || n > len(s.events) {
		n = len(s.events)
	}
	out := make([]Event, n)
	copy(out, s.events[len(s.events)-n:])
	return out
}

// ForAgent returns every recorded event for a given agent, in order.
// This is the query an incident review starts with.
func (s *InMemorySink) ForAgent(agentRef string) []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Event
	for _, e := range s.events {
		if e.AgentRef == agentRef {
			out = append(out, e)
		}
	}
	return out
}

var _ Sink = (*InMemorySink)(nil)
