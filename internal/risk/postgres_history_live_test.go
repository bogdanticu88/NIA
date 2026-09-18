package risk

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"
)

// The live tests for PostgresCallHistory. Skipped unless
// NIA_RISK_TEST_DATABASE_URL points at a real Postgres, same posture as
// every other live test in this repo, and run in CI against a Postgres
// service container, see .github/workflows/ci.yml.
//
// These cannot be replaced by the in-memory tests. The property that
// matters for a multi-replica deployment is that two independent store
// handles, standing in for two gateway processes, agree about what is
// novel, and a mutex in one process proves nothing about that.
func liveHistory(t *testing.T) (*PostgresCallHistory, context.Context) {
	t.Helper()
	dsn := os.Getenv("NIA_RISK_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NIA_RISK_TEST_DATABASE_URL not set, skipping live Postgres test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	h, err := NewPostgresCallHistory(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPostgresCallHistory: %v", err)
	}
	t.Cleanup(func() { _ = h.Close() })
	return h, ctx
}

// liveRef keeps each test's agent distinct: this database is shared and
// long-lived, and history is the whole point of the type, so a reused
// ref would let one run decide another run's answers.
func liveRef(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("agent:hist-%d", time.Now().UnixNano())
}

func TestPostgresCallHistory_Live(t *testing.T) {
	h, ctx := liveHistory(t)
	ref := liveRef(t)
	base := time.Now()

	first, err := h.Observe(ctx, ref, "a", base, time.Minute)
	if err != nil {
		t.Fatalf("Observe a: %v", err)
	}
	if !first.NovelTool || first.NovelTransition || first.RecentCalls != 0 {
		t.Fatalf("first call = %+v, want novel tool, no transition, no recent calls", first)
	}

	second, err := h.Observe(ctx, ref, "b", base.Add(time.Second), time.Minute)
	if err != nil {
		t.Fatalf("Observe b: %v", err)
	}
	if !second.NovelTool || !second.NovelTransition {
		t.Fatalf("second call = %+v, want both novel tool and novel transition", second)
	}
	if second.RecentCalls != 1 {
		t.Fatalf("RecentCalls = %d, want 1", second.RecentCalls)
	}

	third, err := h.Observe(ctx, ref, "a", base.Add(2*time.Second), time.Minute)
	if err != nil {
		t.Fatalf("Observe a again: %v", err)
	}
	if third.NovelTool {
		t.Fatal("NovelTool = true for a tool already recorded")
	}
	if !third.NovelTransition {
		t.Fatal("NovelTransition = false for b -> a, an ordering never recorded")
	}
	if third.RecentCalls != 2 {
		t.Fatalf("RecentCalls = %d, want 2", third.RecentCalls)
	}
}

// TestPostgresCallHistory_Live_TwoHandlesShareOneBaseline is the whole
// reason this implementation exists: two independent handles are two
// gateway replicas, and the second must not see as novel what the first
// already recorded.
func TestPostgresCallHistory_Live_TwoHandlesShareOneBaseline(t *testing.T) {
	first, ctx := liveHistory(t)
	second, _ := liveHistory(t)
	ref := liveRef(t)
	base := time.Now()

	if _, err := first.Observe(ctx, ref, "invoice.read", base, time.Minute); err != nil {
		t.Fatalf("first handle Observe: %v", err)
	}
	obs, err := second.Observe(ctx, ref, "invoice.read", base.Add(time.Second), time.Minute)
	if err != nil {
		t.Fatalf("second handle Observe: %v", err)
	}
	if obs.NovelTool {
		t.Fatal("the second handle reported NovelTool for a tool the first already recorded, the baseline is not shared")
	}
	if obs.RecentCalls != 1 {
		t.Fatalf("RecentCalls = %d on the second handle, want 1: the first handle's call should be visible", obs.RecentCalls)
	}
}

// TestPostgresCallHistory_Live_ConcurrentFirstCallsReportNovelOnce is
// the cross-process version of the in-memory concurrency test, run
// across two handles so the advisory lock, not a Go mutex, is what is
// actually being proven.
func TestPostgresCallHistory_Live_ConcurrentFirstCallsReportNovelOnce(t *testing.T) {
	a, ctx := liveHistory(t)
	b, _ := liveHistory(t)
	ref := liveRef(t)
	at := time.Now()

	const n = 20
	results := make([]Observation, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			h := a
			if i%2 == 1 {
				h = b
			}
			results[i], errs[i] = h.Observe(ctx, ref, "invoice.read", at, time.Minute)
		}(i)
	}
	wg.Wait()

	novel := 0
	for i := range results {
		if errs[i] != nil {
			t.Fatalf("Observe #%d: %v", i, errs[i])
		}
		if results[i].NovelTool {
			novel++
		}
	}
	if novel != 1 {
		t.Fatalf("%d of %d concurrent first calls across two handles reported NovelTool, want exactly 1", novel, n)
	}
}

func TestPostgresCallHistory_Live_RecentCallsAgeOutOfTheWindow(t *testing.T) {
	h, ctx := liveHistory(t)
	ref := liveRef(t)
	base := time.Now()

	for i := 0; i < 4; i++ {
		if _, err := h.Observe(ctx, ref, "a", base.Add(time.Duration(i)*time.Second), time.Minute); err != nil {
			t.Fatalf("Observe #%d: %v", i, err)
		}
	}
	obs, err := h.Observe(ctx, ref, "a", base.Add(time.Hour), time.Minute)
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if obs.RecentCalls != 0 {
		t.Fatalf("RecentCalls = %d an hour after the burst, want 0", obs.RecentCalls)
	}
}
