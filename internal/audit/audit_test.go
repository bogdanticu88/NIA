package audit

import (
	"context"
	"testing"
	"time"
)

func TestInMemorySink_AppendAndRecent(t *testing.T) {
	s := NewInMemorySink(10)
	ctx := context.Background()

	for i, action := range []string{"agent.registered", "grant.written", "agent.killed"} {
		if err := s.Append(ctx, Event{Action: action, AgentRef: "agent:x", At: time.Unix(int64(i), 0)}); err != nil {
			t.Fatalf("Append(%d): %v", i, err)
		}
	}

	got, err := s.Recent(ctx, 10)
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("Recent returned %d events, want 3", len(got))
	}
	// Oldest first: the third append (agent.killed) happened last, so it
	// must come last in the result, not first.
	if got[0].Action != "agent.registered" || got[2].Action != "agent.killed" {
		t.Fatalf("Recent order wrong: got %v", got)
	}
}

func TestInMemorySink_RecentCapsAtAvailable(t *testing.T) {
	s := NewInMemorySink(10)
	ctx := context.Background()
	_ = s.Append(ctx, Event{Action: "a", AgentRef: "agent:x"})

	got, err := s.Recent(ctx, 50)
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("Recent(50) with one stored event returned %d, want 1", len(got))
	}
}

func TestInMemorySink_EvictsOldestPastMax(t *testing.T) {
	s := NewInMemorySink(2)
	ctx := context.Background()
	_ = s.Append(ctx, Event{Action: "first", AgentRef: "agent:x"})
	_ = s.Append(ctx, Event{Action: "second", AgentRef: "agent:x"})
	_ = s.Append(ctx, Event{Action: "third", AgentRef: "agent:x"})

	got, err := s.Recent(ctx, 10)
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d events after eviction, want 2 (max)", len(got))
	}
	if got[0].Action != "second" || got[1].Action != "third" {
		t.Fatalf("wrong events survived eviction: %v", got)
	}
}

func TestInMemorySink_ForAgentFiltersBySubject(t *testing.T) {
	s := NewInMemorySink(10)
	ctx := context.Background()
	_ = s.Append(ctx, Event{Action: "agent.registered", AgentRef: "agent:billing"})
	_ = s.Append(ctx, Event{Action: "agent.registered", AgentRef: "agent:other"})
	_ = s.Append(ctx, Event{Action: "agent.killed", AgentRef: "agent:billing"})

	got, err := s.ForAgent(ctx, "agent:billing")
	if err != nil {
		t.Fatalf("ForAgent: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("ForAgent(billing) returned %d events, want 2", len(got))
	}
	for _, e := range got {
		if e.AgentRef != "agent:billing" {
			t.Fatalf("ForAgent leaked an event for a different agent: %+v", e)
		}
	}
}

func TestInMemorySink_ForAgentUnknownRefReturnsEmpty(t *testing.T) {
	s := NewInMemorySink(10)
	ctx := context.Background()
	_ = s.Append(ctx, Event{Action: "agent.registered", AgentRef: "agent:billing"})

	got, err := s.ForAgent(ctx, "agent:does-not-exist")
	if err != nil {
		t.Fatalf("ForAgent: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("ForAgent for an unregistered ref returned %d events, want 0", len(got))
	}
}

func TestInMemorySink_AppendFillsInMissingTimestamp(t *testing.T) {
	s := NewInMemorySink(10)
	ctx := context.Background()
	before := time.Now()
	_ = s.Append(ctx, Event{Action: "agent.registered", AgentRef: "agent:x"})
	after := time.Now()

	got, _ := s.Recent(ctx, 1)
	if len(got) != 1 {
		t.Fatalf("expected one event, got %d", len(got))
	}
	if got[0].At.Before(before) || got[0].At.After(after) {
		t.Fatalf("Append did not fill in a zero timestamp: got %v, want between %v and %v", got[0].At, before, after)
	}
}
