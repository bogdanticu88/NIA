package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bogdanticu88/nia/internal/audit"
	"github.com/bogdanticu88/nia/internal/credentials"
)

// TestForwarding_ValidAgent_ReachesARealDownstreamToolAndReturnsItsResponse
// is the first of the two proofs the hardening directive asked for:
// valid agent -> gateway -> real tool -> response -> agent, driven
// through a real httptest.Server standing in for the downstream tool
// (a real HTTP backend, not a mocked Forwarder) and a real
// credentialResolver + credentials.Store, not a header-trust shortcut.
// This is what proves handleToolCall's forwarding step is a real
// network hop, not a stubbed success returned from inside the process.
func TestForwarding_ValidAgent_ReachesARealDownstreamToolAndReturnsItsResponse(t *testing.T) {
	var downstreamCalls int
	downstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		downstreamCalls++
		if r.URL.Path != "/invoice.read" {
			t.Errorf("downstream saw path %q, want /invoice.read", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"invoice_total": 4200})
	}))
	defer downstream.Close()

	store := credentials.NewInMemoryStore()
	cred, secret, err := store.Issue(context.Background(), "agent:billing", credentials.KindAPIKey, 0)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	pol := &fakePolicyClient{allowed: true}
	g := newCredentialGateway(pol, store)
	g.forwarder = NewHTTPForwarder(downstream.URL)

	req := httptest.NewRequest(http.MethodPost, "/tools/invoice.read/call", nil)
	req.Header.Set("Authorization", "Bearer "+cred.ID+"."+secret)
	req.SetPathValue("tool", "invoice.read")
	rec := httptest.NewRecorder()
	g.handleToolCall(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if downstreamCalls != 1 {
		t.Fatalf("downstream was called %d times, want exactly 1", downstreamCalls)
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshaling response: %v", err)
	}
	result, ok := resp["result"].(map[string]any)
	if !ok {
		t.Fatalf("resp[\"result\"] = %v (%T), want the real downstream body", resp["result"], resp["result"])
	}
	if result["invoice_total"] != float64(4200) {
		t.Fatalf("result[\"invoice_total\"] = %v, want 4200, the actual downstream response, not a stubbed one", result["invoice_total"])
	}
	if resp["downstream_status"] != float64(http.StatusOK) {
		t.Fatalf("resp[\"downstream_status\"] = %v, want 200", resp["downstream_status"])
	}
}

// TestForwarding_KilledAgent_DeniedBeforeDownstreamIsEverContacted is
// the second proof: killed/revoked agent -> gateway -> DENIED ->
// downstream NOT contacted. The credential itself is still otherwise
// valid, only the owning agent's kill state is set, the same
// independent IsKilled check credentialResolver already makes (see
// authn.go and docs/SECURITY_INVARIANTS.md invariant 11). If forwarding
// were wired in ahead of, or in parallel with, that check instead of
// strictly after it, this test would see the downstream get called
// anyway, that's exactly the alternate-path regression this test
// exists to catch.
func TestForwarding_KilledAgent_DeniedBeforeDownstreamIsEverContacted(t *testing.T) {
	var downstreamCalls int
	downstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		downstreamCalls++
		w.WriteHeader(http.StatusOK)
	}))
	defer downstream.Close()

	store := credentials.NewInMemoryStore()
	cred, secret, err := store.Issue(context.Background(), "agent:billing", credentials.KindAPIKey, 0)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	pol := &fakePolicyClient{allowed: true, isKilled: true}
	g := newCredentialGateway(pol, store)
	g.forwarder = NewHTTPForwarder(downstream.URL)

	req := httptest.NewRequest(http.MethodPost, "/tools/invoice.read/call", nil)
	req.Header.Set("Authorization", "Bearer "+cred.ID+"."+secret)
	req.SetPathValue("tool", "invoice.read")
	rec := httptest.NewRecorder()
	g.handleToolCall(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401: a killed agent's otherwise-valid credential must not authenticate: %s", rec.Code, rec.Body.String())
	}
	if downstreamCalls != 0 {
		t.Fatalf("downstream was called %d times, want 0: a killed agent must never reach the real downstream tool", downstreamCalls)
	}
	if pol.calls != 0 {
		t.Fatalf("policy.Check was called %d times, want 0: authorization must never even run for a killed agent's request", pol.calls)
	}
}

// TestForwarding_RevokedCredential_DeniedBeforeDownstreamIsEverContacted
// is the same proof for a revoked-but-not-killed credential: the agent
// itself isn't killed, this one specific credential was revoked, the
// gateway's credential-state check (independent of the kill check
// above) must still stop the request before it ever reaches
// g.forwarder.Forward.
func TestForwarding_RevokedCredential_DeniedBeforeDownstreamIsEverContacted(t *testing.T) {
	var downstreamCalls int
	downstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		downstreamCalls++
		w.WriteHeader(http.StatusOK)
	}))
	defer downstream.Close()

	store := credentials.NewInMemoryStore()
	cred, secret, err := store.Issue(context.Background(), "agent:billing", credentials.KindAPIKey, 0)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := store.Revoke(context.Background(), cred.ID, "operator", "compromised"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	pol := &fakePolicyClient{allowed: true}
	g := newCredentialGateway(pol, store)
	g.forwarder = NewHTTPForwarder(downstream.URL)

	req := httptest.NewRequest(http.MethodPost, "/tools/invoice.read/call", nil)
	req.Header.Set("Authorization", "Bearer "+cred.ID+"."+secret)
	req.SetPathValue("tool", "invoice.read")
	rec := httptest.NewRecorder()
	g.handleToolCall(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401: a revoked credential must not authenticate: %s", rec.Code, rec.Body.String())
	}
	if downstreamCalls != 0 {
		t.Fatalf("downstream was called %d times, want 0: a revoked credential must never reach the real downstream tool", downstreamCalls)
	}
}

// TestForwarding_ToolDenied_DeniedBeforeDownstreamIsEverContacted covers
// the ordinary authorization-denial case, not just the identity ones
// above: an authenticated agent with no grant for the tool must also
// never reach the downstream.
func TestForwarding_ToolDenied_DeniedBeforeDownstreamIsEverContacted(t *testing.T) {
	var downstreamCalls int
	downstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		downstreamCalls++
		w.WriteHeader(http.StatusOK)
	}))
	defer downstream.Close()

	store := credentials.NewInMemoryStore()
	cred, secret, err := store.Issue(context.Background(), "agent:billing", credentials.KindAPIKey, 0)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	pol := &fakePolicyClient{allowed: false}
	g := newCredentialGateway(pol, store)
	g.forwarder = NewHTTPForwarder(downstream.URL)

	req := httptest.NewRequest(http.MethodPost, "/tools/invoice.delete/call", nil)
	req.Header.Set("Authorization", "Bearer "+cred.ID+"."+secret)
	req.SetPathValue("tool", "invoice.delete")
	rec := httptest.NewRecorder()
	g.handleToolCall(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: %s", rec.Code, rec.Body.String())
	}
	if downstreamCalls != 0 {
		t.Fatalf("downstream was called %d times, want 0: an unauthorized call must never reach the real downstream tool", downstreamCalls)
	}
}

// TestForwarding_DownstreamUnreachable_Returns502AndAuditsIt covers the
// forwarding-itself-fails path: the call was legitimately authorized,
// the downstream just isn't answering, this must surface as its own
// outcome, not a silent success and not folded into a denial.
func TestForwarding_DownstreamUnreachable_Returns502AndAuditsIt(t *testing.T) {
	unreachable := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := unreachable.URL
	unreachable.Close() // nothing is listening here anymore

	pol := &fakePolicyClient{allowed: true}
	g, sink := newTestGateway(pol)
	g.forwarder = NewHTTPForwarder(url)

	rec := doToolCall(g, "agent:billing", "invoice.read")
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502: %s", rec.Code, rec.Body.String())
	}

	events, _ := sink.Recent(context.Background(), 10)
	found := false
	for _, e := range events {
		if e.Action == "gateway.downstream_unreachable" {
			found = true
		}
	}
	if !found {
		t.Fatalf("got audit events %v, want one with Action=gateway.downstream_unreachable", events)
	}
}

// TestForwarding_DownstreamSuccess_AuditsDownstreamOk and the two tests
// below it exercise inspectAndAuditDownstream's actual branches through
// the full handler, not just the helper directly, proving the audit
// trail records what a real downstream response looked like: ok, a
// server error, and a client error are three different audit actions,
// not one generic "forwarded" line that can't tell them apart later.
func TestForwarding_DownstreamSuccess_AuditsDownstreamOk(t *testing.T) {
	downstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer downstream.Close()

	pol := &fakePolicyClient{allowed: true}
	g, sink := newTestGateway(pol)
	g.forwarder = NewHTTPForwarder(downstream.URL)

	rec := doToolCall(g, "agent:billing", "invoice.read")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	assertAuditAction(t, sink, "gateway.downstream_ok")
}

func TestForwarding_DownstreamServerError_AuditsDownstreamErrorAndMirrorsStatus(t *testing.T) {
	downstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"database unavailable"}`))
	}))
	defer downstream.Close()

	pol := &fakePolicyClient{allowed: true}
	g, sink := newTestGateway(pol)
	g.forwarder = NewHTTPForwarder(downstream.URL)

	rec := doToolCall(g, "agent:billing", "invoice.read")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500, the gateway mirrors the downstream's own status: %s", rec.Code, rec.Body.String())
	}
	assertAuditAction(t, sink, "gateway.downstream_error")
	assertAuditAction(t, sink, "gateway.downstream_reported_error")
}

func TestForwarding_DownstreamClientError_AuditsDownstreamRejected(t *testing.T) {
	downstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer downstream.Close()

	pol := &fakePolicyClient{allowed: true}
	g, sink := newTestGateway(pol)
	g.forwarder = NewHTTPForwarder(downstream.URL)

	rec := doToolCall(g, "agent:billing", "invoice.read")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	assertAuditAction(t, sink, "gateway.downstream_rejected")
}

func assertAuditAction(t *testing.T, sink interface {
	Recent(ctx context.Context, n int) ([]audit.Event, error)
}, action string) {
	t.Helper()
	events, err := sink.Recent(context.Background(), 20)
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	for _, e := range events {
		if e.Action == action {
			return
		}
	}
	t.Fatalf("got audit events %v, want one with Action=%s", events, action)
}
