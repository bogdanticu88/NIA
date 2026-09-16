package monitoring

import (
	"context"
	"sync"
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

func TestObserve_RiskAccumulatesAcrossCalls_CrossesThresholdOnTheThirdCall(t *testing.T) {
	sink := audit.NewInMemorySink(10)
	m := NewMonitor(Threshold{FlagAt: 5, RevokeAt: 10, KillAt: 20}, policy.NewInMemoryClient(), nil, sink)
	ctx := context.Background()

	for i, want := range []Action{ActionNone, ActionNone, ActionFlag} {
		action, err := m.Observe(ctx, newScore("agent:billing", 2), "")
		if err != nil {
			t.Fatalf("Observe #%d: %v", i, err)
		}
		if action != want {
			t.Fatalf("Observe #%d: action = %q, want %q", i, action, want)
		}
	}
	if got := m.CumulativeRisk("agent:billing"); got != 6 {
		t.Fatalf("CumulativeRisk = %v, want 6 (three calls at 2 each)", got)
	}
}

func TestObserve_RiskAccumulationIsPerAgent(t *testing.T) {
	sink := audit.NewInMemorySink(10)
	m := NewMonitor(Threshold{FlagAt: 5, RevokeAt: 10, KillAt: 20}, policy.NewInMemoryClient(), nil, sink)
	ctx := context.Background()

	if _, err := m.Observe(ctx, newScore("agent:billing", 4), ""); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	action, err := m.Observe(ctx, newScore("agent:reporting", 4), "")
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if action != ActionNone {
		t.Fatalf("action = %q, want none, agent:reporting's own total is only 4, below the flag threshold of 5", action)
	}
	if got := m.CumulativeRisk("agent:billing"); got != 4 {
		t.Fatalf("CumulativeRisk(agent:billing) = %v, want 4", got)
	}
	if got := m.CumulativeRisk("agent:reporting"); got != 4 {
		t.Fatalf("CumulativeRisk(agent:reporting) = %v, want 4", got)
	}
}

func TestObserve_KillResetsCumulativeRisk(t *testing.T) {
	sink := audit.NewInMemorySink(10)
	m := NewMonitor(Threshold{FlagAt: 5, RevokeAt: 10, KillAt: 20}, policy.NewInMemoryClient(), nil, sink)
	ctx := context.Background()

	if _, err := m.Observe(ctx, newScore("agent:billing", 20), "INC-003"); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if got := m.CumulativeRisk("agent:billing"); got != 0 {
		t.Fatalf("CumulativeRisk after a kill = %v, want 0", got)
	}
}

func TestObserve_RevokeDoesNotResetCumulativeRisk(t *testing.T) {
	sink := audit.NewInMemorySink(10)
	m := NewMonitor(Threshold{FlagAt: 5, RevokeAt: 10, KillAt: 20}, policy.NewInMemoryClient(), nil, sink)
	ctx := context.Background()

	if _, err := m.Observe(ctx, newScore("agent:billing", 10), ""); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if got := m.CumulativeRisk("agent:billing"); got != 10 {
		t.Fatalf("CumulativeRisk after a revoke = %v, want 10, a revoke should not reset the running total, only a kill does", got)
	}
}

func TestObserve_RiskAccumulationIsRaceSafe(t *testing.T) {
	sink := audit.NewInMemorySink(1000)
	m := NewMonitor(Threshold{FlagAt: 1_000_000, RevokeAt: 2_000_000, KillAt: 3_000_000}, policy.NewInMemoryClient(), nil, sink)
	ctx := context.Background()

	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			if _, err := m.Observe(ctx, newScore("agent:billing", 1), ""); err != nil {
				t.Errorf("Observe: %v", err)
			}
		}()
	}
	wg.Wait()

	if got := m.CumulativeRisk("agent:billing"); got != n {
		t.Fatalf("CumulativeRisk = %v, want %d, concurrent Observe calls must not lose an update", got, n)
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
