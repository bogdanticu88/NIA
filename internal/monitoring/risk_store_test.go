package monitoring

import (
	"context"
	"sync"
	"testing"
)

func TestInMemoryRiskStore_AccumulateAddsAndReturnsTheNewTotal(t *testing.T) {
	s := NewInMemoryRiskStore()
	ctx := context.Background()

	total, err := s.Accumulate(ctx, "agent:billing", 3)
	if err != nil {
		t.Fatalf("Accumulate: %v", err)
	}
	if total != 3 {
		t.Fatalf("Accumulate returned %v, want 3", total)
	}

	total, err = s.Accumulate(ctx, "agent:billing", 4)
	if err != nil {
		t.Fatalf("Accumulate: %v", err)
	}
	if total != 7 {
		t.Fatalf("Accumulate returned %v, want 7 (3+4)", total)
	}
}

func TestInMemoryRiskStore_GetOnAnUnknownAgentIsZeroNotAnError(t *testing.T) {
	s := NewInMemoryRiskStore()
	got, err := s.Get(context.Background(), "agent:never-seen")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != 0 {
		t.Fatalf("Get on an unknown agent = %v, want 0", got)
	}
}

func TestInMemoryRiskStore_ResetClearsTheRunningTotal(t *testing.T) {
	s := NewInMemoryRiskStore()
	ctx := context.Background()
	if _, err := s.Accumulate(ctx, "agent:billing", 10); err != nil {
		t.Fatalf("Accumulate: %v", err)
	}
	if err := s.Reset(ctx, "agent:billing"); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	got, err := s.Get(ctx, "agent:billing")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != 0 {
		t.Fatalf("Get after Reset = %v, want 0", got)
	}
}

func TestInMemoryRiskStore_ResetOnAnUnknownAgentIsANoOp(t *testing.T) {
	s := NewInMemoryRiskStore()
	if err := s.Reset(context.Background(), "agent:never-seen"); err != nil {
		t.Fatalf("Reset on an agent with no history: %v", err)
	}
}

func TestInMemoryRiskStore_TrackedAgentsCountsDistinctAgents(t *testing.T) {
	s := NewInMemoryRiskStore()
	ctx := context.Background()
	if n, err := s.TrackedAgents(ctx); err != nil || n != 0 {
		t.Fatalf("TrackedAgents on a fresh store = (%d, %v), want (0, nil)", n, err)
	}
	if _, err := s.Accumulate(ctx, "agent:billing", 1); err != nil {
		t.Fatalf("Accumulate: %v", err)
	}
	if _, err := s.Accumulate(ctx, "agent:reporting", 1); err != nil {
		t.Fatalf("Accumulate: %v", err)
	}
	if _, err := s.Accumulate(ctx, "agent:billing", 1); err != nil {
		t.Fatalf("Accumulate: %v", err)
	}
	n, err := s.TrackedAgents(ctx)
	if err != nil {
		t.Fatalf("TrackedAgents: %v", err)
	}
	if n != 2 {
		t.Fatalf("TrackedAgents = %d, want 2 distinct agents", n)
	}
}

// TestInMemoryRiskStore_ConcurrentAccumulateNeverLosesAnUpdate is the
// same property monitoring_test.go's own
// TestObserve_RiskAccumulationIsRaceSafe already covered through
// Monitor.Observe before this pass, kept here too now that the running
// total is a separate, independently swappable type: this is the
// specific guarantee a PostgresRiskStore has to preserve as well, see
// postgres_risk_store_live_test.go's own concurrent test for the same
// property proven against real Postgres.
func TestInMemoryRiskStore_ConcurrentAccumulateNeverLosesAnUpdate(t *testing.T) {
	s := NewInMemoryRiskStore()
	ctx := context.Background()

	const n = 100
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			if _, err := s.Accumulate(ctx, "agent:billing", 1); err != nil {
				t.Errorf("Accumulate: %v", err)
			}
		}()
	}
	wg.Wait()

	got, err := s.Get(ctx, "agent:billing")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != n {
		t.Fatalf("Get after %d concurrent Accumulate(1) calls = %v, want %d", n, got, n)
	}
}

var _ RiskStore = (*InMemoryRiskStore)(nil)
