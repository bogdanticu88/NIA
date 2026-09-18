package risk

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestInMemoryCallHistory_FirstCallIsNovelWithNoTransition(t *testing.T) {
	h := NewInMemoryCallHistory()
	obs, err := h.Observe(context.Background(), "agent:billing", "invoice.read", time.Now(), 0)
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if !obs.NovelTool {
		t.Fatal("NovelTool = false on an agent's very first call")
	}
	if obs.NovelTransition {
		t.Fatal("NovelTransition = true on a first call, there is no previous tool to transition from")
	}
}

func TestInMemoryCallHistory_RepeatToolIsNeitherNovelNorATransition(t *testing.T) {
	h := NewInMemoryCallHistory()
	ctx := context.Background()
	now := time.Now()

	if _, err := h.Observe(ctx, "agent:billing", "invoice.read", now, 0); err != nil {
		t.Fatalf("first Observe: %v", err)
	}
	obs, err := h.Observe(ctx, "agent:billing", "invoice.read", now.Add(time.Second), 0)
	if err != nil {
		t.Fatalf("second Observe: %v", err)
	}
	if obs.NovelTool {
		t.Fatal("NovelTool = true for a tool this agent already called")
	}
	if obs.NovelTransition {
		t.Fatal("NovelTransition = true for a repeat of the same tool, calling one tool twice in a row is not a new ordering")
	}
}

func TestInMemoryCallHistory_NewOrderingOfFamiliarToolsIsATransition(t *testing.T) {
	h := NewInMemoryCallHistory()
	now := time.Now()

	// Teach it A then B, so both tools are familiar and A -> B is seen.
	mustObserve(t, h, "agent:billing", "a", now)
	mustObserve(t, h, "agent:billing", "b", now.Add(time.Second))
	// Back to A: B -> A is a new ordering even though both tools are old.
	obs := mustObserve(t, h, "agent:billing", "a", now.Add(2*time.Second))
	if obs.NovelTool {
		t.Fatal("NovelTool = true for a tool already called")
	}
	if !obs.NovelTransition {
		t.Fatal("NovelTransition = false for b -> a, an ordering this agent had never used")
	}
	// A -> B again, already seen, so neither fires.
	obs = mustObserve(t, h, "agent:billing", "b", now.Add(3*time.Second))
	if obs.NovelTool || obs.NovelTransition {
		t.Fatalf("got %+v for a repeat of the a -> b transition, want neither signal", obs)
	}
}

// TestInMemoryCallHistory_SelfRepeatDoesNotHideALaterRealTransition is
// the edge the self-transition suppression could plausibly get wrong:
// A, A, B must still see A -> B as new, not swallow it because the
// middle call was a repeat.
func TestInMemoryCallHistory_SelfRepeatDoesNotHideALaterRealTransition(t *testing.T) {
	h := NewInMemoryCallHistory()
	now := time.Now()
	mustObserve(t, h, "agent:billing", "a", now)
	mustObserve(t, h, "agent:billing", "a", now.Add(time.Second))
	obs := mustObserve(t, h, "agent:billing", "b", now.Add(2*time.Second))
	if !obs.NovelTransition {
		t.Fatal("NovelTransition = false for a -> b after a repeated a")
	}
}

func TestInMemoryCallHistory_HistoryIsPerAgent(t *testing.T) {
	h := NewInMemoryCallHistory()
	now := time.Now()
	mustObserve(t, h, "agent:billing", "invoice.read", now)
	obs := mustObserve(t, h, "agent:payroll", "invoice.read", now)
	if !obs.NovelTool {
		t.Fatal("NovelTool = false for another agent's first call to the same tool")
	}
}

func TestInMemoryCallHistory_RecentCallsCountsInsideTheWindowOnly(t *testing.T) {
	h := NewInMemoryCallHistory()
	ctx := context.Background()
	base := time.Now()
	window := time.Minute

	for i := 0; i < 3; i++ {
		if _, err := h.Observe(ctx, "agent:billing", "invoice.read", base.Add(time.Duration(i)*time.Second), window); err != nil {
			t.Fatalf("Observe #%d: %v", i, err)
		}
	}
	// A fourth call, still inside the window: three before it.
	obs, err := h.Observe(ctx, "agent:billing", "invoice.read", base.Add(4*time.Second), window)
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if obs.RecentCalls != 3 {
		t.Fatalf("RecentCalls = %d, want 3", obs.RecentCalls)
	}
	// A fifth, an hour later: everything before it has aged out.
	obs, err = h.Observe(ctx, "agent:billing", "invoice.read", base.Add(time.Hour), window)
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if obs.RecentCalls != 0 {
		t.Fatalf("RecentCalls = %d after the window passed, want 0", obs.RecentCalls)
	}
}

func TestInMemoryCallHistory_ZeroWindowSkipsRateTrackingEntirely(t *testing.T) {
	h := NewInMemoryCallHistory()
	now := time.Now()
	mustObserve(t, h, "agent:billing", "invoice.read", now)
	obs := mustObserve(t, h, "agent:billing", "invoice.read", now.Add(time.Second))
	if obs.RecentCalls != 0 {
		t.Fatalf("RecentCalls = %d with rate tracking off, want 0", obs.RecentCalls)
	}
}

// TestInMemoryCallHistory_ConcurrentFirstCallsReportNovelExactlyOnce is
// the race Observe's single-method shape exists to close: a read then a
// separate write would let both goroutines see the tool as absent and
// both score novel_tool, doubling a signal that feeds a kill threshold.
func TestInMemoryCallHistory_ConcurrentFirstCallsReportNovelExactlyOnce(t *testing.T) {
	h := NewInMemoryCallHistory()
	ctx := context.Background()
	now := time.Now()

	const n = 50
	var wg sync.WaitGroup
	results := make([]Observation, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			obs, err := h.Observe(ctx, "agent:billing", "invoice.read", now, time.Minute)
			if err != nil {
				t.Errorf("Observe: %v", err)
				return
			}
			results[i] = obs
		}(i)
	}
	wg.Wait()

	novel := 0
	for _, r := range results {
		if r.NovelTool {
			novel++
		}
	}
	if novel != 1 {
		t.Fatalf("%d of %d concurrent first calls reported NovelTool, want exactly 1", novel, n)
	}
}

func mustObserve(t *testing.T, h CallHistory, agentRef, tool string, at time.Time) Observation {
	t.Helper()
	obs, err := h.Observe(context.Background(), agentRef, tool, at, 0)
	if err != nil {
		t.Fatalf("Observe(%s, %s): %v", agentRef, tool, err)
	}
	return obs
}
