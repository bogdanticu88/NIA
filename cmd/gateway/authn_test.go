package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bogdanticu88/nia/internal/credentials"
	"github.com/bogdanticu88/nia/internal/identity"
)

// failingVerifyStore fails only Verify, everything else passes through
// to the wrapped store, the shape needed to prove a credential store
// outage fails closed rather than being treated as "no identity."
type failingVerifyStore struct{ credentials.Store }

var errStoreDown = errors.New("credentials store unreachable")

func (failingVerifyStore) Verify(context.Context, string, string) (credentials.Credential, error) {
	return credentials.Credential{}, errStoreDown
}

func bearerHeader(id, secret string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + id + "." + secret}
}

func TestCredentialResolver_ValidCredentialResolvesTheOwningAgent(t *testing.T) {
	store := credentials.NewInMemoryStore()
	cred, secret, err := store.Issue(context.Background(), "agent:billing", credentials.KindAPIKey, 0)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	pol := &fakePolicyClient{isKilled: false}
	r := credentialResolver{creds: store, pol: pol}

	resolved, err := r.Resolve(context.Background(), identity.ResolveContext{Headers: bearerHeader(cred.ID, secret)})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if resolved == nil {
		t.Fatalf("Resolve returned nil, want a resolved identity for a valid credential")
	}
	if resolved.Ref != "agent:billing" {
		t.Fatalf("Ref = %q, want agent:billing", resolved.Ref)
	}
	if resolved.Assurance != identity.AssuranceStrong {
		t.Fatalf("Assurance = %v, want Strong for a real credential-backed resolution", resolved.Assurance)
	}
	if resolved.CredentialID != cred.ID {
		t.Fatalf("CredentialID = %q, want %q", resolved.CredentialID, cred.ID)
	}
}

func TestCredentialResolver_NoAuthorizationHeaderIsUnresolvedNotAnError(t *testing.T) {
	r := credentialResolver{creds: credentials.NewInMemoryStore(), pol: &fakePolicyClient{}}
	resolved, err := r.Resolve(context.Background(), identity.ResolveContext{})
	if err != nil {
		t.Fatalf("Resolve: %v, want no error for a missing header", err)
	}
	if resolved != nil {
		t.Fatalf("Resolve = %+v, want nil for a missing Authorization header", resolved)
	}
}

func TestCredentialResolver_WrongSchemeIsUnresolved(t *testing.T) {
	r := credentialResolver{creds: credentials.NewInMemoryStore(), pol: &fakePolicyClient{}}
	resolved, err := r.Resolve(context.Background(), identity.ResolveContext{Headers: map[string]string{
		"Authorization": "Basic dXNlcjpwYXNz",
	}})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if resolved != nil {
		t.Fatalf("Resolve = %+v, want nil for a non-Bearer scheme", resolved)
	}
}

func TestCredentialResolver_MalformedTokenIsUnresolved(t *testing.T) {
	r := credentialResolver{creds: credentials.NewInMemoryStore(), pol: &fakePolicyClient{}}
	for _, bad := range []string{"Bearer ", "Bearer no-dot-here", "Bearer .secret", "Bearer id."} {
		resolved, err := r.Resolve(context.Background(), identity.ResolveContext{Headers: map[string]string{"Authorization": bad}})
		if err != nil {
			t.Fatalf("Resolve(%q): %v, want no error", bad, err)
		}
		if resolved != nil {
			t.Fatalf("Resolve(%q) = %+v, want nil", bad, resolved)
		}
	}
}

func TestCredentialResolver_FakeAgentRefWithNoCredentialCannotAuthenticate(t *testing.T) {
	// The exact attack the security hardening directive named directly:
	// an attacker who used to just set X-Agent-Ref: agent:someone-else
	// and be treated as that agent. Presenting a made-up id.secret pair
	// that was never issued must not resolve to anything.
	store := credentials.NewInMemoryStore()
	r := credentialResolver{creds: store, pol: &fakePolicyClient{}}
	resolved, err := r.Resolve(context.Background(), identity.ResolveContext{
		Headers: bearerHeader("not-a-real-id", "not-a-real-secret"),
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if resolved != nil {
		t.Fatalf("Resolve = %+v, want nil for a fabricated credential", resolved)
	}
}

func TestCredentialResolver_WrongSecretForARealIDCannotAuthenticate(t *testing.T) {
	store := credentials.NewInMemoryStore()
	cred, _, err := store.Issue(context.Background(), "agent:billing", credentials.KindAPIKey, 0)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	r := credentialResolver{creds: store, pol: &fakePolicyClient{}}
	resolved, err := r.Resolve(context.Background(), identity.ResolveContext{
		Headers: bearerHeader(cred.ID, "definitely-the-wrong-secret"),
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if resolved != nil {
		t.Fatalf("Resolve = %+v, want nil for a real id with the wrong secret", resolved)
	}
}

func TestCredentialResolver_CredentialFromAnotherAgentAuthenticatesAsThatAgentOnly(t *testing.T) {
	// Proves the resolver can't be tricked into attributing agent:a's
	// call to agent:b just because the caller wishes it were so: the
	// resolved Ref always comes from the credential record itself, a
	// caller has no way to name a different Ref, there is no ref field
	// in the request at all anymore.
	store := credentials.NewInMemoryStore()
	aCred, aSecret, _ := store.Issue(context.Background(), "agent:a", credentials.KindAPIKey, 0)
	r := credentialResolver{creds: store, pol: &fakePolicyClient{}}

	resolved, err := r.Resolve(context.Background(), identity.ResolveContext{Headers: bearerHeader(aCred.ID, aSecret)})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if resolved.Ref != "agent:a" {
		t.Fatalf("Ref = %q, want agent:a, a credential can only ever resolve to the agent it was issued for", resolved.Ref)
	}
}

func TestCredentialResolver_RevokedCredentialCannotAuthenticate(t *testing.T) {
	store := credentials.NewInMemoryStore()
	cred, secret, err := store.Issue(context.Background(), "agent:billing", credentials.KindAPIKey, 0)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := store.Revoke(context.Background(), cred.ID, "bogdan", "compromised"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	r := credentialResolver{creds: store, pol: &fakePolicyClient{}}
	resolved, err := r.Resolve(context.Background(), identity.ResolveContext{Headers: bearerHeader(cred.ID, secret)})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if resolved != nil {
		t.Fatalf("Resolve = %+v, want nil for a revoked credential", resolved)
	}
}

func TestCredentialResolver_CredentialForAKilledAgentCannotAuthenticate(t *testing.T) {
	// The credential itself is still Active in credentials.Store, this
	// specifically proves the second, independent check against
	// policy.Client.IsKilled, not just Verify's own status check.
	store := credentials.NewInMemoryStore()
	cred, secret, err := store.Issue(context.Background(), "agent:billing", credentials.KindAPIKey, 0)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	pol := &fakePolicyClient{isKilled: true}
	r := credentialResolver{creds: store, pol: pol}

	resolved, err := r.Resolve(context.Background(), identity.ResolveContext{Headers: bearerHeader(cred.ID, secret)})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if resolved != nil {
		t.Fatalf("Resolve = %+v, want nil for a credential whose agent is killed", resolved)
	}
	got, getErr := store.Get(context.Background(), cred.ID)
	if getErr != nil {
		t.Fatalf("Get: %v", getErr)
	}
	if got.Status != credentials.StatusActive {
		t.Fatalf("credential Status = %q, want this test to prove the kill check independent of the credential's own stored status", got.Status)
	}
}

func TestCredentialResolver_StoreFailureFailsClosedNotUnresolved(t *testing.T) {
	// A store outage must not look identical to "no identity," it must
	// be reported as an error so handleToolCall returns 500, not 401,
	// and critically never proceeds as if the call were authenticated.
	r := credentialResolver{creds: failingVerifyStore{}, pol: &fakePolicyClient{}}
	resolved, err := r.Resolve(context.Background(), identity.ResolveContext{Headers: bearerHeader("id", "secret")})
	if err == nil {
		t.Fatalf("Resolve returned no error for a failed credential store, want fail-closed")
	}
	if resolved != nil {
		t.Fatalf("Resolve = %+v, want nil alongside the error", resolved)
	}
}

func TestCredentialResolver_KillCheckFailureFailsClosed(t *testing.T) {
	store := credentials.NewInMemoryStore()
	cred, secret, err := store.Issue(context.Background(), "agent:billing", credentials.KindAPIKey, 0)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	pol := &fakePolicyClient{isKilledErr: errors.New("tessera unreachable")}
	r := credentialResolver{creds: store, pol: pol}

	resolved, err := r.Resolve(context.Background(), identity.ResolveContext{Headers: bearerHeader(cred.ID, secret)})
	if err == nil {
		t.Fatalf("Resolve returned no error when the kill check itself failed, want fail-closed")
	}
	if resolved != nil {
		t.Fatalf("Resolve = %+v, want nil alongside the error", resolved)
	}
}

// --- End to end: the whole gateway, not just the resolver in isolation ---

// newCredentialGateway builds a gateway wired the way main() actually
// wires one by default: credentialResolver, not headerResolver. Every
// other test in this package uses newTestGateway (headerResolver) to
// isolate handleToolCall's authorization logic from authentication;
// these tests are the ones that prove authentication itself, end to
// end through a real HTTP request, not just the resolver called
// directly.
func newCredentialGateway(pol *fakePolicyClient, store credentials.Store) *gateway {
	g, _ := newTestGateway(pol)
	g.resolver = credentialResolver{creds: store, pol: pol}
	g.pol = pol
	return g
}

func TestHandleToolCall_FakeAgentRefAloneNoLongerAuthenticates(t *testing.T) {
	// This is the regression test for the exact vulnerability the
	// security hardening directive opened with: sending X-Agent-Ref
	// used to be sufficient. With credentialResolver as the default, an
	// Authorization header is required at all, X-Agent-Ref is not even
	// read by this resolver.
	store := credentials.NewInMemoryStore()
	pol := &fakePolicyClient{allowed: true}
	g := newCredentialGateway(pol, store)

	req := httptest.NewRequest(http.MethodPost, "/tools/invoice.read/call", nil)
	req.Header.Set("X-Agent-Ref", "agent:billing")
	req.SetPathValue("tool", "invoice.read")
	rec := httptest.NewRecorder()
	g.handleToolCall(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401: a bare X-Agent-Ref header must not authenticate anymore: %s", rec.Code, rec.Body.String())
	}
	if pol.calls != 0 {
		t.Fatalf("policy.Check was called %d times, want 0: authorization must never run for an unauthenticated request", pol.calls)
	}
}

func TestHandleToolCall_ValidCredentialProceedsToAuthorization(t *testing.T) {
	store := credentials.NewInMemoryStore()
	cred, secret, err := store.Issue(context.Background(), "agent:billing", credentials.KindAPIKey, 0)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	pol := &fakePolicyClient{allowed: true}
	g := newCredentialGateway(pol, store)

	req := httptest.NewRequest(http.MethodPost, "/tools/invoice.read/call", nil)
	req.Header.Set("Authorization", "Bearer "+cred.ID+"."+secret)
	req.SetPathValue("tool", "invoice.read")
	rec := httptest.NewRecorder()
	g.handleToolCall(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if pol.calls != 1 {
		t.Fatalf("policy.Check called %d times, want 1", pol.calls)
	}
}

func TestHandleToolCall_RevokedCredentialIsDeniedBeforeAuthorizationEverRuns(t *testing.T) {
	store := credentials.NewInMemoryStore()
	cred, secret, err := store.Issue(context.Background(), "agent:billing", credentials.KindAPIKey, 0)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := store.Revoke(context.Background(), cred.ID, "bogdan", "stolen"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	pol := &fakePolicyClient{allowed: true} // would allow if it were ever asked
	g := newCredentialGateway(pol, store)

	req := httptest.NewRequest(http.MethodPost, "/tools/invoice.read/call", nil)
	req.Header.Set("Authorization", "Bearer "+cred.ID+"."+secret)
	req.SetPathValue("tool", "invoice.read")
	rec := httptest.NewRecorder()
	g.handleToolCall(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for a revoked credential: %s", rec.Code, rec.Body.String())
	}
	if pol.calls != 0 {
		t.Fatalf("policy.Check was called %d times, want 0: a revoked credential must never reach authorization", pol.calls)
	}
}

func TestHandleToolCall_KilledAgentsCredentialIsDeniedEvenThoughItsOwnStatusIsActive(t *testing.T) {
	store := credentials.NewInMemoryStore()
	cred, secret, err := store.Issue(context.Background(), "agent:billing", credentials.KindAPIKey, 0)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	pol := &fakePolicyClient{allowed: true, isKilled: true}
	g := newCredentialGateway(pol, store)

	req := httptest.NewRequest(http.MethodPost, "/tools/invoice.read/call", nil)
	req.Header.Set("Authorization", "Bearer "+cred.ID+"."+secret)
	req.SetPathValue("tool", "invoice.read")
	rec := httptest.NewRecorder()
	g.handleToolCall(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401: a killed agent's credential must not authenticate even if the credential row itself is still Active: %s", rec.Code, rec.Body.String())
	}
}
