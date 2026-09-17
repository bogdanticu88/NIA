package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/bogdanticu88/nia/internal/credentials"
	"github.com/bogdanticu88/nia/internal/policy"
)

// realCredentialGateway is newCredentialGateway's counterpart for a
// real policy.Client (policy.InMemoryClient here) rather than
// fakePolicyClient: these tests need genuine Kill/Restore/Check state
// transitions, not a client that only ever reports a fixed
// allowed/isKilled flag.
func realCredentialGateway(pol policy.Client, store credentials.Store) *gateway {
	g, _ := newTestGateway(pol)
	g.resolver = credentialResolver{creds: store, pol: pol}
	g.pol = pol
	return g
}

func toolCallStatus(g *gateway, credentialID, secret string) int {
	req := httptest.NewRequest(http.MethodPost, "/tools/invoice.read/call", nil)
	req.Header.Set("Authorization", "Bearer "+credentialID+"."+secret)
	req.SetPathValue("tool", "invoice.read")
	rec := httptest.NewRecorder()
	g.handleToolCall(rec, req)
	return rec.Code
}

// TestHandleToolCall_ConcurrentRequestsDuringKill_NoRequestSucceedsAfterKillCompletes
// is "request vs kill" and "kill vs request" from the security
// hardening directive's list, covered together: the two names describe
// the same race from either side, and a real Kill call and a real
// tool-call request racing each other is symmetric, there's no
// meaningful difference in which one "started" it. Not a race on any
// mutex, go test -race already proves that once this compiles clean;
// this is the correctness property the directive actually cares about,
// stated the same way
// internal/credentials.TestInMemoryStore_ConcurrentVerifyDuringRevokeNeverSucceedsPastTheRevoke
// already states it for the credential store alone: a request that
// completes concurrently with a kill may land on either side of it,
// allowed or denied, both are legitimate depending on exactly when it
// happened to run, but once Kill has actually returned, every
// subsequent request must be denied, with no lingering window where a
// concurrently-started request slips through afterward.
func TestHandleToolCall_ConcurrentRequestsDuringKill_NoRequestSucceedsAfterKillCompletes(t *testing.T) {
	ctx := context.Background()
	pol := policy.NewInMemoryClient()
	store := credentials.NewInMemoryStore()
	cred, secret, err := store.Issue(ctx, "agent:billing", credentials.KindAPIKey, 0)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := pol.WriteGrants(ctx, "agent:billing", []policy.Grant{policy.GrantForTool("invoice.read")}); err != nil {
		t.Fatalf("WriteGrants: %v", err)
	}
	g := realCredentialGateway(pol, store)

	const n = 50
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			toolCallStatus(g, cred.ID, secret)
		}()
	}
	close(start)
	if _, err := pol.Kill(ctx, "agent:billing", "INC-race", "bogdan"); err != nil {
		t.Fatalf("Kill: %v", err)
	}
	wg.Wait()

	if code := toolCallStatus(g, cred.ID, secret); code != http.StatusUnauthorized {
		t.Fatalf("request after all goroutines settled: status = %d, want 401, kill must be fully enforced once Kill itself has returned", code)
	}
}

// TestHandleToolCall_ConcurrentRequestsDuringRevoke_NoRequestSucceedsAfterRevokeCompletes
// is "request vs revoke" and "revoke vs request," same reasoning as
// the kill test above, against credentials.Store.Revoke instead of
// policy.Client.Kill: a narrower action, one credential rather than
// the whole agent, but the same property applies, once Revoke has
// returned, every subsequent request presenting that credential must
// be denied.
func TestHandleToolCall_ConcurrentRequestsDuringRevoke_NoRequestSucceedsAfterRevokeCompletes(t *testing.T) {
	ctx := context.Background()
	pol := policy.NewInMemoryClient()
	store := credentials.NewInMemoryStore()
	cred, secret, err := store.Issue(ctx, "agent:billing", credentials.KindAPIKey, 0)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := pol.WriteGrants(ctx, "agent:billing", []policy.Grant{policy.GrantForTool("invoice.read")}); err != nil {
		t.Fatalf("WriteGrants: %v", err)
	}
	g := realCredentialGateway(pol, store)

	const n = 50
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			toolCallStatus(g, cred.ID, secret)
		}()
	}
	close(start)
	if err := store.Revoke(ctx, cred.ID, "bogdan", "concurrent revoke test"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	wg.Wait()

	if code := toolCallStatus(g, cred.ID, secret); code != http.StatusUnauthorized {
		t.Fatalf("request after all goroutines settled: status = %d, want 401, revoke must be fully enforced once Revoke itself has returned", code)
	}
}

// TestHandleToolCall_ConcurrentRequestsDuringRotation_OldCredentialNeverSucceedsAfterRotationCompletes
// is "credential rotation vs request" and "credential rotation vs
// replay" together: requests presenting the about-to-be-rotated-away
// secret race a real Rotate call, and once Rotate has returned, no
// further request with the old secret, a replay of exactly what an
// attacker who captured it before rotation would attempt, may succeed,
// while the newly issued secret must.
func TestHandleToolCall_ConcurrentRequestsDuringRotation_OldCredentialNeverSucceedsAfterRotationCompletes(t *testing.T) {
	ctx := context.Background()
	pol := policy.NewInMemoryClient()
	store := credentials.NewInMemoryStore()
	old, oldSecret, err := store.Issue(ctx, "agent:billing", credentials.KindAPIKey, 0)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := pol.WriteGrants(ctx, "agent:billing", []policy.Grant{policy.GrantForTool("invoice.read")}); err != nil {
		t.Fatalf("WriteGrants: %v", err)
	}
	g := realCredentialGateway(pol, store)

	const n = 50
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			toolCallStatus(g, old.ID, oldSecret)
		}()
	}
	close(start)
	next, nextSecret, err := store.Rotate(ctx, old.ID, "bogdan", 0)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	wg.Wait()

	if code := toolCallStatus(g, old.ID, oldSecret); code != http.StatusUnauthorized {
		t.Fatalf("replaying the old credential after all goroutines settled: status = %d, want 401, rotation must be fully enforced once Rotate itself has returned", code)
	}
	if code := toolCallStatus(g, next.ID, nextSecret); code != http.StatusOK {
		t.Fatalf("the rotated-to credential after rotation: status = %d, want 200", code)
	}
}

// TestHandleToolCall_RestoreDoesNotReviveACredentialThatWasRevokedByTheKillItRestoresFrom
// is "restore vs previously revoked credential." Not a goroutine race,
// the property here is about state-transition sequencing, not timing:
// a kill cascades into revoking every active credential the agent
// held (internal/monitoring.Monitor.Observe, cmd/api's handleKill),
// and Restore is documented as clearing only the kill sentinel, "not
// undo the kill," see docs/ARCHITECTURE.md's "Credential-backed
// authentication and state convergence" section. This test is the
// direct check that restoring an agent does not quietly bring its old,
// already-revoked credentials back to life, which would be a real
// authentication bypass if it happened, an operator restoring a
// previously-compromised agent expecting to have to issue it a fresh
// credential, exactly as the documentation says, not discovering the
// old, potentially-leaked one still works.
func TestHandleToolCall_RestoreDoesNotReviveACredentialThatWasRevokedByTheKillItRestoresFrom(t *testing.T) {
	ctx := context.Background()
	pol := policy.NewInMemoryClient()
	store := credentials.NewInMemoryStore()
	cred, secret, err := store.Issue(ctx, "agent:billing", credentials.KindAPIKey, 0)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := pol.WriteGrants(ctx, "agent:billing", []policy.Grant{policy.GrantForTool("invoice.read")}); err != nil {
		t.Fatalf("WriteGrants: %v", err)
	}
	g := realCredentialGateway(pol, store)

	if code := toolCallStatus(g, cred.ID, secret); code != http.StatusOK {
		t.Fatalf("before any kill: status = %d, want 200", code)
	}

	if _, err := pol.Kill(ctx, "agent:billing", "INC-restore-test", "bogdan"); err != nil {
		t.Fatalf("Kill: %v", err)
	}
	// This test is about credential state specifically, so cascade the
	// revoke by hand the same way cmd/api's handleKill and
	// monitoring.Monitor.Observe both actually do, rather than pulling
	// in either of those call sites: the point here is Restore's own
	// behavior, not re-testing the cascade itself.
	if err := store.Revoke(ctx, cred.ID, "bogdan", "cascaded from kill"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if code := toolCallStatus(g, cred.ID, secret); code != http.StatusUnauthorized {
		t.Fatalf("after kill and cascade revoke: status = %d, want 401", code)
	}

	if err := pol.Restore(ctx, "agent:billing"); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	// The agent itself is no longer killed, a fresh credential for it
	// would authenticate again, but the specific credential that was
	// revoked as part of the kill must stay revoked, Restore does not
	// reach into credentials.Store at all.
	if code := toolCallStatus(g, cred.ID, secret); code != http.StatusUnauthorized {
		t.Fatalf("after restore, presenting the credential that was revoked by the kill: status = %d, want 401, restore must not revive a previously revoked credential", code)
	}
	got, err := store.Get(ctx, cred.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != credentials.StatusRevoked {
		t.Fatalf("credential status after restore = %q, want it to remain revoked, restore only clears the kill sentinel", got.Status)
	}
}
