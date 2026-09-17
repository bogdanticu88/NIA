package main

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/bogdanticu88/nia/internal/audit"
	"github.com/bogdanticu88/nia/internal/credentials"
	"github.com/bogdanticu88/nia/internal/incident"
	"github.com/bogdanticu88/nia/internal/metrics"
	"github.com/bogdanticu88/nia/internal/monitoring"
	"github.com/bogdanticu88/nia/internal/policy"
)

// twoInstanceDeployment builds two independent *gateway values that
// share nothing except three backing stores: pol, creds, and risk.
// That's deliberate, it's the actual shape of two gateway replicas in
// a real deployment. Each replica has its own process memory (its own
// HistoryScorer novelty tracking, its own metrics registry, its own
// audit sink here so the test can tell which instance wrote what), and
// the only thing making them behave like one logical security control
// plane instead of two independent, inconsistent ones is that
// pol/creds/risk are the same store, reachable from both. In a real
// deployment that sharing happens over the network (Tessera for pol,
// Postgres for creds and risk, see docs/ARCHITECTURE.md's "Distributed
// state" section); constructing two *gateway values that hold the same
// Go interface value is the direct, in-process way to prove the code
// paths that consume those interfaces behave correctly when the state
// behind them is shared, without needing two more OS processes and a
// running Tessera/Postgres for every CI run. This pass also verified
// the same property against two real nia-gateway processes sharing a
// real Tessera and a real Postgres, see README.md's phase entry for
// that run's results, this test is what CI actually runs on every
// push.
func twoInstanceDeployment(pol policy.Client, creds credentials.Store, riskStore monitoring.RiskStore, thresholds monitoring.Threshold) (a, b *gateway) {
	build := func() *gateway {
		sink := audit.NewInMemorySink(50)
		incidents := incident.NewInMemoryStore()
		monitor := monitoring.NewMonitorWithRiskStore(thresholds, pol, creds, incidents, sink, riskStore)
		reg := metrics.NewRegistry()
		return &gateway{
			resolver:   credentialResolver{creds: creds, pol: pol},
			pol:        pol,
			scorer:     fakeScorer{value: 6},
			monitor:    monitor,
			incidents:  incidents,
			auditLog:   sink,
			metrics:    newGatewayMetrics(reg),
			metricsReg: reg,
		}
	}
	return build(), build()
}

func toolCallWithCredential(g *gateway, credentialID, secret, tool string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "/tools/"+tool+"/call", nil)
	req.Header.Set("Authorization", "Bearer "+credentialID+"."+secret)
	req.SetPathValue("tool", tool)
	rec := httptest.NewRecorder()
	g.handleToolCall(rec, req)
	return rec
}

// TestDistributed_RiskAccumulatesAcrossTwoGatewayInstancesSharingARiskStore
// is the risk-enforcement-state half of the directive's distributed
// state requirement: an agent's cumulative risk must not reset to zero
// just because the next call happened to land on a different replica.
// Each of the two instances below only ever sees one call for this
// agent; if the running total were process-local (the behavior before
// this pass, see risk_store.go's own doc comment), neither call alone
// would cross the kill threshold and nothing would happen. Because the
// two instances share one RiskStore, the second call's Observe sees the
// first instance's own contribution already there and crosses it.
func TestDistributed_RiskAccumulatesAcrossTwoGatewayInstancesSharingARiskStore(t *testing.T) {
	ctx := context.Background()
	pol := policy.NewInMemoryClient()
	creds := credentials.NewInMemoryStore()
	risk := monitoring.NewInMemoryRiskStore()
	// FlagAt low enough that one call alone already flags, KillAt high
	// enough that one call alone (value 6, see fakeScorer above) never
	// reaches it on its own, only two calls' combined total does.
	thresholds := monitoring.Threshold{FlagAt: 3, RevokeAt: 1_000, KillAt: 10}

	instanceA, instanceB := twoInstanceDeployment(pol, creds, risk, thresholds)

	cred, secret, err := creds.Issue(ctx, "agent:billing", credentials.KindAPIKey, 0)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := pol.WriteGrants(ctx, "agent:billing", []policy.Grant{policy.GrantForTool("invoices.read")}); err != nil {
		t.Fatalf("WriteGrants: %v", err)
	}

	// Call #1 through instance A: cumulative goes to 6, above FlagAt
	// (3) but below KillAt (10), so this alone must not kill the agent.
	rec := toolCallWithCredential(instanceA, cred.ID, secret, "invoices.read")
	if rec.Code != 200 {
		t.Fatalf("instance A call #1: status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if killed, _ := pol.IsKilled(ctx, "agent:billing"); killed {
		t.Fatal("agent killed after only one call worth of risk (6 < KillAt 10), the threshold logic itself is broken, not what this test is checking")
	}

	// Call #2 through instance B, a completely separate *gateway value
	// with its own Monitor and its own HistoryScorer, sharing only
	// pol/creds/risk with instance A. If risk were process-local to
	// instance B, its own running total would start over at 0, hit 6,
	// stay below KillAt, and nothing would happen. Because risk is
	// shared, instance B's Observe sees instance A's 6 plus its own 6,
	// crosses KillAt (10), and kills the agent itself.
	rec = toolCallWithCredential(instanceB, cred.ID, secret, "invoices.read")
	if rec.Code != 200 {
		t.Fatalf("instance B call #2: status = %d, want 200 (the call itself was authorized before monitoring ran): %s", rec.Code, rec.Body.String())
	}
	killed, err := pol.IsKilled(ctx, "agent:billing")
	if err != nil {
		t.Fatalf("IsKilled: %v", err)
	}
	if !killed {
		t.Fatal("agent not killed after two calls' combined risk (6+6=12) crossed KillAt (10) across two instances sharing one risk store, distributed risk accumulation is not working")
	}
}

// TestDistributed_KillPerformedThroughOneGatewayInstanceIsEnforcedByTheOther
// is the exact scenario the directive's own diagram describes: Gateway
// A triggers a kill, and a request hitting Gateway B, which never
// called Kill itself, must independently observe it and deny, with no
// cross-instance call between A and B, only the shared pol/creds state
// either one would reach over the network in a real deployment.
func TestDistributed_KillPerformedThroughOneGatewayInstanceIsEnforcedByTheOther(t *testing.T) {
	ctx := context.Background()
	pol := policy.NewInMemoryClient()
	creds := credentials.NewInMemoryStore()
	risk := monitoring.NewInMemoryRiskStore()
	thresholds := monitoring.Threshold{FlagAt: 3, RevokeAt: 1_000, KillAt: 10}

	instanceA, instanceB := twoInstanceDeployment(pol, creds, risk, thresholds)

	cred, secret, err := creds.Issue(ctx, "agent:billing", credentials.KindAPIKey, 0)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := pol.WriteGrants(ctx, "agent:billing", []policy.Grant{policy.GrantForTool("invoices.read")}); err != nil {
		t.Fatalf("WriteGrants: %v", err)
	}

	// Drive the kill entirely through instance A: two calls, both
	// through the same instance this time, whose combined risk (6+6)
	// crosses KillAt and triggers instance A's own Monitor to call
	// pol.Kill and cascade-revoke the credential, exactly as
	// monitoring.Monitor.Observe already does.
	if rec := toolCallWithCredential(instanceA, cred.ID, secret, "invoices.read"); rec.Code != 200 {
		t.Fatalf("instance A call #1: status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if rec := toolCallWithCredential(instanceA, cred.ID, secret, "invoices.read"); rec.Code != 200 {
		t.Fatalf("instance A call #2: status = %d, want 200 (authorized before monitoring ran, monitoring's kill is a side effect, not a denial of this call): %s", rec.Code, rec.Body.String())
	}
	if killed, _ := pol.IsKilled(ctx, "agent:billing"); !killed {
		t.Fatal("setup broken: instance A's own two calls should have crossed KillAt and killed the agent")
	}

	// Gateway A -> kill agent -> shared state. Now prove Gateway B
	// enforces it: instance B never called Kill, never saw either of
	// the two calls that triggered it, and still must deny, both at the
	// credential-authentication layer (credentialResolver's own
	// IsKilled check, see authn.go) and at the tool-authorization layer
	// (pol.Check on a killed agent's now-empty grant set), the same two
	// independent checks TestForwarding_KilledAgent_... already proves
	// for a single instance, exercised here across two.
	rec := toolCallWithCredential(instanceB, cred.ID, secret, "invoices.read")
	if rec.Code != 401 {
		t.Fatalf("instance B, after a kill performed entirely through instance A: status = %d, want 401: %s", rec.Code, rec.Body.String())
	}

	// The credential itself must also read as revoked through
	// instance B's own view of the shared credentials.Store, not just
	// "this one call got denied."
	got, err := creds.Get(ctx, cred.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != credentials.StatusRevoked {
		t.Fatalf("credential status = %q after instance A's kill cascaded a revoke, want revoked, observed through the same shared store instance B also reads", got.Status)
	}
}
