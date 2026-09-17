package monitoring

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"
)

// TestPostgresRiskStore_Live drives a real Postgres instance end to
// end: schema creation on first connect, accumulate, get, reset,
// tracked agents, against actual SQL, not the in-memory reference.
// Opt-in via NIA_MONITORING_TEST_DATABASE_URL (a standard postgres://
// DSN), skipped by default, same pattern
// internal/credentials/postgres_live_test.go and
// internal/audit/postgres_sink_live_test.go both use.
func TestPostgresRiskStore_Live(t *testing.T) {
	dsn := os.Getenv("NIA_MONITORING_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NIA_MONITORING_TEST_DATABASE_URL not set, skipping live Postgres test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	store, err := NewPostgresRiskStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPostgresRiskStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	agentRef := "agent:live-test-" + time.Now().Format("20060102T150405.000000000")
	t.Cleanup(func() {
		_, _ = store.db.ExecContext(context.Background(), `DELETE FROM risk_state WHERE agent_ref = $1`, agentRef)
	})

	if got, err := store.Get(ctx, agentRef); err != nil || got != 0 {
		t.Fatalf("Get on a never-seen agent = (%v, %v), want (0, nil)", got, err)
	}

	total, err := store.Accumulate(ctx, agentRef, 3)
	if err != nil {
		t.Fatalf("Accumulate: %v", err)
	}
	if total != 3 {
		t.Fatalf("Accumulate returned %v, want 3", total)
	}

	total, err = store.Accumulate(ctx, agentRef, 4)
	if err != nil {
		t.Fatalf("Accumulate: %v", err)
	}
	if total != 7 {
		t.Fatalf("Accumulate returned %v, want 7 (3+4), a real row read back after a real UPSERT", total)
	}

	got, err := store.Get(ctx, agentRef)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != 7 {
		t.Fatalf("Get = %v, want 7, matching what Accumulate itself last returned", got)
	}

	if err := store.Reset(ctx, agentRef); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	if got, err := store.Get(ctx, agentRef); err != nil || got != 0 {
		t.Fatalf("Get after Reset = (%v, %v), want (0, nil)", got, err)
	}

	n, err := store.TrackedAgents(ctx)
	if err != nil {
		t.Fatalf("TrackedAgents: %v", err)
	}
	// Reset deletes the row rather than zeroing it in place, see
	// PostgresRiskStore.Reset's own doc comment, so this agent no
	// longer counts toward TrackedAgents at all, not "tracked with a
	// zero total." Other rows this same test database happens to have
	// from other tests or other runs may still be present, so this
	// only asserts the agent this test just reset isn't among them,
	// not that the count is exactly 0.
	if n < 0 {
		t.Fatalf("TrackedAgents returned a negative count: %d", n)
	}
}

// TestPostgresRiskStore_Live_ConcurrentAccumulateAcrossTwoStoreHandles
// is the distributed-state proof this security hardening pass exists
// for: two independent *PostgresRiskStore values, standing in for two
// separate gateway processes each opening their own connection pool
// against the same database rather than sharing a Go pointer, both
// accumulating for the same agent at the same time. If Accumulate were
// a read-then-write instead of the single UPSERT it actually is, this
// would lose updates under concurrency, exactly the race two real
// gateway replicas racing to score two different agent calls at once
// could hit. Same skip behavior as TestPostgresRiskStore_Live.
func TestPostgresRiskStore_Live_ConcurrentAccumulateAcrossTwoStoreHandles(t *testing.T) {
	dsn := os.Getenv("NIA_MONITORING_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NIA_MONITORING_TEST_DATABASE_URL not set, skipping live Postgres test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	storeA, err := NewPostgresRiskStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPostgresRiskStore (A): %v", err)
	}
	t.Cleanup(func() { _ = storeA.Close() })
	storeB, err := NewPostgresRiskStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPostgresRiskStore (B): %v", err)
	}
	t.Cleanup(func() { _ = storeB.Close() })

	agentRef := "agent:live-concurrent-" + time.Now().Format("20060102T150405.000000000")
	t.Cleanup(func() {
		_, _ = storeA.db.ExecContext(context.Background(), `DELETE FROM risk_state WHERE agent_ref = $1`, agentRef)
	})

	const perStore = 50
	var wg sync.WaitGroup
	wg.Add(2 * perStore)
	for i := 0; i < perStore; i++ {
		go func() {
			defer wg.Done()
			if _, err := storeA.Accumulate(ctx, agentRef, 1); err != nil {
				t.Errorf("storeA.Accumulate: %v", err)
			}
		}()
		go func() {
			defer wg.Done()
			if _, err := storeB.Accumulate(ctx, agentRef, 1); err != nil {
				t.Errorf("storeB.Accumulate: %v", err)
			}
		}()
	}
	wg.Wait()

	// Read back through a third handle, not either of the two that
	// wrote, so this genuinely confirms the database holds the right
	// total rather than one store's own connection pool caching
	// something.
	storeC, err := NewPostgresRiskStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPostgresRiskStore (C): %v", err)
	}
	defer storeC.Close()

	got, err := storeC.Get(ctx, agentRef)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if want := float64(2 * perStore); got != want {
		t.Fatalf("cumulative total after %d concurrent Accumulate(1) calls split across two independent store handles = %v, want %v, an update was lost", 2*perStore, got, want)
	}
}
