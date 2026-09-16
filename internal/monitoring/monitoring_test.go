package monitoring

import (
	"context"
	"testing"
	"time"

	"github.com/bogdanticu88/nia/internal/audit"
	"github.com/bogdanticu88/nia/internal/credentials"
	"github.com/bogdanticu88/nia/internal/policy"
	"github.com/bogdanticu88/nia/internal/risk"
)

func newScore(agentRef string, value float64) risk.Score {
	return risk.Score{AgentRef: agentRef, Value: value, ScoredAt: time.Now()}
}

func TestObserve_BelowFlagThreshold_NoActionNoAudit(t *testing.T) {
	sink := audit.NewInMemorySink(10)
	m := NewMonitor(Threshold{FlagAt: 5, RevokeAt: 10, KillAt: 20}, policy.NewInMemoryClient(), nil, sink)

	action, err := m.Observe(context.Background(), newScore("agent:billing", 1), "")
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if action != ActionNone {
		t.Fatalf("action = %q, want none", action)
	}
	events, _ := sink.Recent(context.Background(), 10)
	if len(events) != 0 {
		t.Fatalf("got %d audit events for a below-threshold score, want 0: %v", len(events), events)
	}
}

func TestObserve_FlagThreshold_AuditedNoEnforcement(t *testing.T) {
	sink := audit.NewInMemorySink(10)
	m := NewMonitor(Threshold{FlagAt: 5, RevokeAt: 10, KillAt: 20}, policy.NewInMemoryClient(), nil, sink)

	action, err := m.Observe(context.Background(), newScore("agent:billing", 5), "")
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if action != ActionFlag {
		t.Fatalf("action = %q, want flag", action)
	}
	events, _ := sink.Recent(context.Background(), 10)
	if len(events) != 1 || events[0].Action != "monitoring.flag" {
		t.Fatalf("got %v, want exactly one monitoring.flag event", events)
	}
}

func TestObserve_KillThreshold_CallsPolicyKillAndAudits(t *testing.T) {
	sink := audit.NewInMemorySink(10)
	pol := policy.NewInMemoryClient()
	ctx := context.Background()

	m := NewMonitor(Threshold{FlagAt: 5, RevokeAt: 10, KillAt: 20}, pol, nil, sink)
	action, err := m.Observe(ctx, newScore("agent:billing", 20), "INC-001")
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if action != ActionKill {
		t.Fatalf("action = %q, want kill", action)
	}

	events, _ := sink.Recent(ctx, 10)
	if len(events) != 1 || events[0].Action != "monitoring.kill" || events[0].Incident != "INC-001" {
		t.Fatalf("got %v, want exactly one monitoring.kill event with Incident=INC-001", events)
	}
}

func TestObserve_RevokeThreshold_NoCredentialStoreConfigured_IsANoOpButAudited(t *testing.T) {
	sink := audit.NewInMemorySink(10)
	m := NewMonitor(Threshold{FlagAt: 5, RevokeAt: 10, KillAt: 20}, policy.NewInMemoryClient(), nil, sink)

	action, err := m.Observe(context.Background(), newScore("agent:billing", 10), "")
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if action != ActionRevoke {
		t.Fatalf("action = %q, want revoke", action)
	}
	events, _ := sink.Recent(context.Background(), 10)
	if len(events) != 1 || events[0].Action != "monitoring.revoke" {
		t.Fatalf("got %v, want exactly one monitoring.revoke event", events)
	}
	if events[0].Detail == "" {
		t.Fatalf("Detail is empty, want it to say plainly that nothing was revoked because no store is configured")
	}
}

func TestObserve_RevokeThreshold_RevokesOnlyActiveCredentialsForThatAgent(t *testing.T) {
	sink := audit.NewInMemorySink(10)
	store := credentials.NewInMemoryStore()
	ctx := context.Background()

	billingCred, err := store.Issue(ctx, "agent:billing", credentials.KindAPIKey, 0)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	alreadyRevoked, err := store.Issue(ctx, "agent:billing", credentials.KindOAuthToken, 0)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := store.Revoke(ctx, alreadyRevoked.ID, "bogdan", "unrelated cleanup"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	otherAgentCred, err := store.Issue(ctx, "agent:reporting", credentials.KindAPIKey, 0)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	m := NewMonitor(Threshold{FlagAt: 5, RevokeAt: 10, KillAt: 20}, policy.NewInMemoryClient(), store, sink)
	action, err := m.Observe(ctx, newScore("agent:billing", 10), "INC-002")
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if action != ActionRevoke {
		t.Fatalf("action = %q, want revoke", action)
	}

	got, err := store.Get(ctx, billingCred.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != credentials.StatusRevoked || got.RevokedBy != "monitoring" {
		t.Fatalf("got %+v, want the active billing credential revoked by monitoring", got)
	}

	other, err := store.Get(ctx, otherAgentCred.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if other.Status != credentials.StatusActive {
		t.Fatalf("got %+v, want agent:reporting's credential left untouched", other)
	}

	events, _ := sink.Recent(ctx, 10)
	if len(events) != 1 || events[0].Action != "monitoring.revoke" {
		t.Fatalf("got %v, want exactly one monitoring.revoke event", events)
	}
}

func TestObserve_RevokeThreshold_NoActiveCredentials_StillAuditsWithZeroCount(t *testing.T) {
	sink := audit.NewInMemorySink(10)
	store := credentials.NewInMemoryStore()
	m := NewMonitor(Threshold{FlagAt: 5, RevokeAt: 10, KillAt: 20}, policy.NewInMemoryClient(), store, sink)

	action, err := m.Observe(context.Background(), newScore("agent:billing", 10), "")
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if action != ActionRevoke {
		t.Fatalf("action = %q, want revoke", action)
	}
	events, _ := sink.Recent(context.Background(), 10)
	if len(events) != 1 || events[0].Action != "monitoring.revoke" {
		t.Fatalf("got %v, want exactly one monitoring.revoke event", events)
	}
}
