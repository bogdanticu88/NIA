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
//
// It also chains every event it appends (see chain.go): each event's
// hash is computed from its own data plus the previous event's hash,
// so InMemorySink implements Chained too, chain_test.go exercises
// Verify against it directly without needing Postgres. Because this
// sink evicts older events past max, its window can genuinely start
// partway through a real chain, not because anything was tampered
// with, just because this is a capacity-bounded, in-memory
// implementation. truncated tracks whether that's ever happened, and
// Chain reports it as StartsAtGenesis=false so Verify doesn't mistake
// routine eviction for a broken chain.
type InMemorySink struct {
	mu        sync.Mutex
	chain     []ChainedEvent // events plus chain metadata, oldest first
	lastHash  string
	truncated bool
	nextSeq   int64
	max       int
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

	prev := s.lastHash
	if prev == "" {
		prev = GenesisHash
	}
	hash := chainHash(evt, prev)
	s.nextSeq++

	s.chain = append(s.chain, ChainedEvent{Event: evt, Seq: s.nextSeq, Hash: hash, PrevHash: prev})
	s.lastHash = hash
	if len(s.chain) > s.max {
		s.chain = s.chain[len(s.chain)-s.max:]
		s.truncated = true
	}
	return nil
}

// Recent returns up to n most recent events, oldest first. Never
// returns an error, it's in-memory; the signature matches Store because
// callers write against the interface, not this concrete type.
func (s *InMemorySink) Recent(_ context.Context, n int) ([]Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n <= 0 || n > len(s.chain) {
		n = len(s.chain)
	}
	out := make([]Event, n)
	for i, ce := range s.chain[len(s.chain)-n:] {
		out[i] = ce.Event
	}
	return out, nil
}

// ForAgent returns every recorded event for a given agent, in order.
// This is the query an incident review starts with.
func (s *InMemorySink) ForAgent(_ context.Context, agentRef string) ([]Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Event
	for _, ce := range s.chain {
		if ce.AgentRef == agentRef {
			out = append(out, ce.Event)
		}
	}
	return out, nil
}

// Chain returns every currently-retained event with its hash-chain
// metadata, see chain.go's Chained interface. StartsAtGenesis is false
// once this sink has ever evicted an event past its capacity, the
// retained window's first entry then genuinely chains from a real,
// just-no-longer-visible predecessor, not from GenesisHash, and Verify
// needs to know that to avoid flagging routine eviction as tampering.
func (s *InMemorySink) Chain(_ context.Context) (Chain, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ChainedEvent, len(s.chain))
	copy(out, s.chain)
	return Chain{Events: out, StartsAtGenesis: !s.truncated}, nil
}

var (
	_ Sink    = (*InMemorySink)(nil)
	_ Store   = (*InMemorySink)(nil)
	_ Chained = (*InMemorySink)(nil)
)

// PostgresSink (postgres_sink.go) is the shared backend: point cmd/api
// and cmd/gateway at the same database via NIA_AUDIT_DATABASE_URL (see
// from_env.go) and "one stream" in the package doc above stops being
// aspirational, both processes read and write the same table instead
// of each keeping its own in-memory history. Wiring that in is
// deployment configuration, not code, see docker-compose.yml and
// README.md's Status section for what's actually been run against a
// real instance.
