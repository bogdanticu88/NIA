package audit

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestPostgresSink_Live drives a real Postgres instance end to end:
// schema creation on first connect, insert, and both read shapes.
// Opt-in via NIA_AUDIT_TEST_DATABASE_URL (a standard postgres:// DSN),
// skipped by default, same pattern as
// internal/policy/tessera_client_live_test.go uses for a real Tessera
// process. deployments/docker-compose.yml's postgres service, once up,
// is reachable from the host at
// postgres://nia:nia@localhost:5433/nia?sslmode=disable.
func TestPostgresSink_Live(t *testing.T) {
	dsn := os.Getenv("NIA_AUDIT_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NIA_AUDIT_TEST_DATABASE_URL not set, skipping live Postgres test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	sink, err := NewPostgresSink(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPostgresSink: %v", err)
	}
	t.Cleanup(func() { _ = sink.Close() })

	// A ref unique to this run, so repeated runs against the same
	// long-lived database don't see each other's leftover rows and
	// don't need any cleanup step of their own.
	agentRef := "agent:live-test-" + time.Now().Format("20060102T150405.000000000")

	events := []Event{
		{Action: "agent.registered", AgentRef: agentRef, Operator: "bogdan", At: time.Now()},
		{Action: "grant.written", AgentRef: agentRef, Operator: "bogdan", Detail: "tool=invoices.read", At: time.Now().Add(time.Second)},
		{Action: "agent.killed", AgentRef: agentRef, Operator: "bogdan", Incident: "INC-LIVE-001", At: time.Now().Add(2 * time.Second)},
	}
	for _, e := range events {
		if err := sink.Append(ctx, e); err != nil {
			t.Fatalf("Append(%s): %v", e.Action, err)
		}
	}

	got, err := sink.ForAgent(ctx, agentRef)
	if err != nil {
		t.Fatalf("ForAgent: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("ForAgent returned %d events, want 3: %v", len(got), got)
	}
	if got[0].Action != "agent.registered" || got[2].Action != "agent.killed" {
		t.Fatalf("ForAgent order wrong: %v", got)
	}
	if got[2].Incident != "INC-LIVE-001" {
		t.Fatalf("Incident = %q, want INC-LIVE-001", got[2].Incident)
	}

	// Recent has to find these same three rows mixed in with whatever
	// else is in the table, proving the ORDER BY ... DESC ... LIMIT
	// then reverse round trip actually preserves oldest-first order and
	// doesn't drop rows at the boundary.
	recent, err := sink.Recent(ctx, 1000)
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	var found []Event
	for _, e := range recent {
		if e.AgentRef == agentRef {
			found = append(found, e)
		}
	}
	if len(found) != 3 {
		t.Fatalf("Recent(1000) contained %d events for %s, want 3: %v", len(found), agentRef, found)
	}
	if found[0].Action != "agent.registered" || found[2].Action != "agent.killed" {
		t.Fatalf("Recent order wrong for this agent's events: %v", found)
	}
}
