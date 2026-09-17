package monitoring

import (
	"context"
	"sync"
)

// RiskStore is where each agent's running cumulative risk total lives,
// the number Monitor.Observe compares against its thresholds. Split out
// from Monitor itself for the same reason internal/credentials and
// internal/audit split storage from decision logic: Monitor's job is
// deciding what a crossed threshold means, RiskStore's job is making
// that running total survive a restart and be visible to every gateway
// process scoring the same agent, not just the one that happens to
// handle the next call.
//
// Before this existed, Monitor kept the running total in a bare
// map[string]float64 guarded by its own mutex, and this package's own
// doc comments called that out plainly as a known scaffold limitation:
// a second gateway replica had its own separate view of what an
// agent's cumulative risk was. That is not a cosmetic gap, it is a
// distributed authorization bypass waiting to be found, an attacker
// (or just load-balanced traffic) spreading tool calls across replicas
// keeps any single replica's own view under the kill threshold
// indefinitely while the agent's real aggregate behavior keeps
// climbing, and the security hardening directive names "risk
// enforcement state" directly as state that must not be process-local
// only. See docs/ARCHITECTURE.md's "Distributed state" section for the
// full review this closes.
//
// InMemoryRiskStore keeps the original process-local behavior, that is
// still the right default for a single-process deployment or a test
// that doesn't care about the distributed case. PostgresRiskStore
// (postgres_risk_store.go) is what closes the gap when
// NIA_RISK_DATABASE_URL is set, see from_env.go.
type RiskStore interface {
	// Accumulate adds value to agentRef's running total and returns the
	// new total, atomically: two concurrent calls for the same agent,
	// whether from goroutines inside one process or from two separate
	// gateway processes sharing this store, must not lose either
	// update.
	Accumulate(ctx context.Context, agentRef string, value float64) (float64, error)

	// Get returns the current running total, 0 if Accumulate has never
	// been called for agentRef or if it was last cleared by Reset.
	Get(ctx context.Context, agentRef string) (float64, error)

	// Reset clears agentRef's running total back to zero. Called only
	// after Monitor actually kills an agent, see Monitor's own doc
	// comment on why a kill, and only a kill, restarts the count.
	Reset(ctx context.Context, agentRef string) error

	// TrackedAgents reports how many agents currently have a nonzero
	// risk history, a cheap gauge for /metrics, not a way to list who
	// they are.
	TrackedAgents(ctx context.Context) (int, error)
}

// InMemoryRiskStore is the reference implementation: a map guarded by a
// mutex, private to whatever one process constructs it. This is the
// default when NIA_RISK_DATABASE_URL is unset, and it's what every test
// in this package uses unless it's specifically exercising the shared,
// multi-instance case.
type InMemoryRiskStore struct {
	mu         sync.Mutex
	cumulative map[string]float64
}

func NewInMemoryRiskStore() *InMemoryRiskStore {
	return &InMemoryRiskStore{cumulative: make(map[string]float64)}
}

func (s *InMemoryRiskStore) Accumulate(_ context.Context, agentRef string, value float64) (float64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cumulative[agentRef] += value
	return s.cumulative[agentRef], nil
}

func (s *InMemoryRiskStore) Get(_ context.Context, agentRef string) (float64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cumulative[agentRef], nil
}

func (s *InMemoryRiskStore) Reset(_ context.Context, agentRef string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.cumulative, agentRef)
	return nil
}

func (s *InMemoryRiskStore) TrackedAgents(_ context.Context) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.cumulative), nil
}

var _ RiskStore = (*InMemoryRiskStore)(nil)
