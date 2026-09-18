package incident

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/bogdanticu88/nia/internal/risk"
)

func liveStore(t *testing.T) (*PostgresStore, context.Context) {
	t.Helper()
	dsn := os.Getenv("NIA_INCIDENT_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NIA_INCIDENT_TEST_DATABASE_URL not set, skipping live Postgres test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	s, err := NewPostgresStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, ctx
}

func liveAgentRef(t *testing.T, s *PostgresStore) string {
	t.Helper()
	ref := fmt.Sprintf("agent:inc-live-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		_, _ = s.db.ExecContext(context.Background(), `DELETE FROM incidents WHERE agent_ref = $1`, ref)
	})
	return ref
}

func TestPostgresStore_Live(t *testing.T) {
	s, ctx := liveStore(t)
	ref := liveAgentRef(t, s)

	created, err := s.Create(ctx, Incident{
		AgentRef:    ref,
		IncidentRef: "auto-risk-1",
		Action:      "kill",
		RiskValue:   3.5,
		Cumulative:  12,
		Signals: []risk.Signal{
			{Name: "novel_tool", Weight: 1},
			{Name: "call_rate", Weight: 2},
			{Name: "novel_transition", Weight: 0.5},
		},
		Reason: "cumulative risk 12 crossed threshold",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.ID == "" {
		t.Fatal("Create returned an empty ID")
	}
	if created.CreatedAt.IsZero() {
		t.Fatal("Create returned a zero CreatedAt")
	}

	got, err := s.Get(ctx, created.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Action != "kill" || got.RiskValue != 3.5 || got.Cumulative != 12 {
		t.Fatalf("got %+v, want the values it was created with", got)
	}
	// The signals are the actual evidence, the part of an incident that
	// says why containment fired. A JSONB round trip that loses them
	// would leave a record that proves nothing.
	if len(got.Signals) != 3 {
		t.Fatalf("Signals = %+v, want the three it was created with", got.Signals)
	}
	if got.Signals[0].Name != "novel_tool" || got.Signals[0].Weight != 1 {
		t.Fatalf("Signals[0] = %+v, want novel_tool weight 1, order or values were lost", got.Signals[0])
	}
	if got.Reason != "cumulative risk 12 crossed threshold" {
		t.Fatalf("Reason = %q", got.Reason)
	}
}

func TestPostgresStore_Live_NotFound(t *testing.T) {
	s, ctx := liveStore(t)
	if _, err := s.Get(ctx, "inc-does-not-exist"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get = %v, want ErrNotFound", err)
	}
}

func TestPostgresStore_Live_ListFiltersByAgentAndOrdersOldestFirst(t *testing.T) {
	s, ctx := liveStore(t)
	mine := liveAgentRef(t, s)
	other := liveAgentRef(t, s)

	base := time.Now().Add(-time.Hour)
	for i := 0; i < 3; i++ {
		if _, err := s.Create(ctx, Incident{
			AgentRef:  mine,
			Action:    "flag",
			Reason:    fmt.Sprintf("mine %d", i),
			CreatedAt: base.Add(time.Duration(i) * time.Minute),
		}); err != nil {
			t.Fatalf("Create mine %d: %v", i, err)
		}
	}
	if _, err := s.Create(ctx, Incident{AgentRef: other, Action: "flag", Reason: "other"}); err != nil {
		t.Fatalf("Create other: %v", err)
	}

	got, err := s.List(ctx, mine, 0)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("List returned %d incidents, want 3 for this agent only", len(got))
	}
	for i, in := range got {
		if in.AgentRef != mine {
			t.Fatalf("List leaked another agent's incident: %+v", in)
		}
		if want := fmt.Sprintf("mine %d", i); in.Reason != want {
			t.Fatalf("incident %d Reason = %q, want %q: the order is not oldest first", i, in.Reason, want)
		}
	}
}

// TestPostgresStore_Live_LimitKeepsTheMostRecent is the behaviour an
// investigation needs from a capped read: the newest incidents, still
// returned oldest first.
func TestPostgresStore_Live_LimitKeepsTheMostRecent(t *testing.T) {
	s, ctx := liveStore(t)
	ref := liveAgentRef(t, s)

	base := time.Now().Add(-time.Hour)
	for i := 0; i < 5; i++ {
		if _, err := s.Create(ctx, Incident{
			AgentRef:  ref,
			Action:    "flag",
			Reason:    fmt.Sprintf("n%d", i),
			CreatedAt: base.Add(time.Duration(i) * time.Minute),
		}); err != nil {
			t.Fatalf("Create %d: %v", i, err)
		}
	}
	got, err := s.List(ctx, ref, 2)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("List returned %d, want 2", len(got))
	}
	if got[0].Reason != "n3" || got[1].Reason != "n4" {
		t.Fatalf("got %q then %q, want the two most recent (n3, n4) in ascending order", got[0].Reason, got[1].Reason)
	}
}

// TestPostgresStore_Live_SurvivesAcrossHandles stands in for both things
// the in-memory store could not do: survive a restart, and be visible
// from a second replica.
func TestPostgresStore_Live_SurvivesAcrossHandles(t *testing.T) {
	first, ctx := liveStore(t)
	ref := liveAgentRef(t, first)

	created, err := first.Create(ctx, Incident{
		AgentRef:   ref,
		Action:     "kill",
		RiskValue:  9,
		Cumulative: 30,
		Signals:    []risk.Signal{{Name: "call_rate", Weight: 2}},
		Reason:     "killed by the first process",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	second, _ := liveStore(t)
	got, err := second.Get(ctx, created.ID)
	if err != nil {
		t.Fatalf("Get through a second handle: %v, the evidence did not outlive the process that wrote it", err)
	}
	if got.Reason != "killed by the first process" || len(got.Signals) != 1 {
		t.Fatalf("got %+v, want the record the first handle wrote", got)
	}
}

func TestPostgresStore_Live_EmptyListIsEmptyNotNil(t *testing.T) {
	s, ctx := liveStore(t)
	ref := liveAgentRef(t, s)
	got, err := s.List(ctx, ref, 0)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if got == nil {
		t.Fatal("List returned nil for an agent with no incidents, the HTTP handler would serve null instead of []")
	}
	if len(got) != 0 {
		t.Fatalf("List returned %d incidents for a fresh agent", len(got))
	}
}
