package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bogdanticu88/nia/internal/credentials"
	"github.com/bogdanticu88/nia/internal/identity"
)

// This file exercises the two convergence fixes the security hardening
// pass added: handleGetAgent trusting a live policy.Client.IsKilled
// check over the registry's own cached State, and both kill paths
// cascading into credential revocation. See docs/ARCHITECTURE.md's
// "Credential-backed authentication and state convergence" for the
// full reasoning, this file is the proof the described behavior is
// what actually runs.

func TestHandleGetAgent_ReportsKilledFromTheLiveSentinelEvenWhenTheRegistryCacheLags(t *testing.T) {
	s := newTestServer()
	mux := s.routes()

	mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/agents", strings.NewReader(`{"ref":"agent:billing","owner":"bogdan"}`)))

	// Kill through s.pol directly, not through POST /policy/kill, the
	// same shape an automatic kill from internal/monitoring takes: it
	// runs inside cmd/gateway, a different process, and has no path to
	// call handleKill or update this process's own AgentRegistry.State.
	// This is the exact scenario the phase 8 demo surfaced as a real
	// gap, see README.md's Status section.
	if _, err := s.pol.Kill(context.Background(), "agent:billing", "INC-AUTO", "monitoring"); err != nil {
		t.Fatalf("pol.Kill: %v", err)
	}

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/agents/agent:billing", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var report agentReport
	if err := json.NewDecoder(rec.Body).Decode(&report); err != nil {
		t.Fatalf("decode response body: %v", err)
	}
	if report.State != identity.StateActive {
		t.Fatalf("registry State = %q, want this test to prove the registry's own cache genuinely never saw the kill", report.State)
	}
	if !report.KillSentinelChecked {
		t.Fatalf("KillSentinelChecked = false, want true: the live policy check succeeded")
	}
	if report.EffectiveState != identity.StateKilled {
		t.Fatalf("EffectiveState = %q, want killed: the live sentinel, not the stale registry cache, must win", report.EffectiveState)
	}
}

func TestHandleKill_CascadesRevocationToEveryActiveCredential(t *testing.T) {
	s := newTestServer()
	mux := s.routes()

	mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/agents", strings.NewReader(`{"ref":"agent:billing","owner":"bogdan"}`)))
	rec1 := httptest.NewRecorder()
	mux.ServeHTTP(rec1, httptest.NewRequest(http.MethodPost, "/agents/agent:billing/credentials", strings.NewReader(`{"kind":"api_key"}`)))
	cred1 := decodeCredential(t, rec1)
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, httptest.NewRequest(http.MethodPost, "/agents/agent:billing/credentials", strings.NewReader(`{"kind":"api_key"}`)))
	cred2 := decodeCredential(t, rec2)
	// A third credential already revoked before the kill, proving the
	// cascade only touches what's still Active rather than blindly
	// revoking every row and reporting a misleading count.
	rec3 := httptest.NewRecorder()
	mux.ServeHTTP(rec3, httptest.NewRequest(http.MethodPost, "/agents/agent:billing/credentials", strings.NewReader(`{"kind":"api_key"}`)))
	cred3 := decodeCredential(t, rec3)
	mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/credentials/"+cred3.ID+"/revoke", strings.NewReader(`{"revoked_by":"bogdan","reason":"already retired"}`)))

	rec := httptest.NewRecorder()
	killReq := `{"agent_ref":"agent:billing","incident":"INC-002","operator":"bogdan"}`
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/policy/kill", strings.NewReader(killReq)))
	if rec.Code != http.StatusOK {
		t.Fatalf("kill status = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/agents/agent:billing/credentials", nil))
	creds := decodeCredentials(t, rec)
	revoked := 0
	for _, c := range creds {
		if c.Status == credentials.StatusRevoked {
			revoked++
		}
	}
	if revoked != 3 {
		t.Fatalf("got %d revoked credentials, want all 3 revoked after the kill (cred1=%s cred2=%s)", revoked, cred1.ID, cred2.ID)
	}

	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/agents/agent:billing/audit", nil))
	events := decodeEvents(t, rec)
	killed := events[len(events)-1]
	if killed.Action != "agent.killed" || !strings.Contains(killed.Detail, "revoked 2 credential(s)") {
		t.Fatalf("got %+v, want agent.killed reporting exactly 2 newly revoked credentials (the third was already revoked)", killed)
	}
}

func TestHandleRestore_ClearsKillSentinelButLeavesGrantsAndCredentialsAlone(t *testing.T) {
	s := newTestServer()
	mux := s.routes()

	mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/agents", strings.NewReader(`{"ref":"agent:billing","owner":"bogdan"}`)))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/agents/agent:billing/credentials", strings.NewReader(`{"kind":"api_key"}`)))
	cred := decodeCredential(t, rec)

	killReq := `{"agent_ref":"agent:billing","incident":"INC-003","operator":"bogdan"}`
	mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/policy/kill", strings.NewReader(killReq)))

	rec = httptest.NewRecorder()
	restoreReq := `{"agent_ref":"agent:billing","operator":"bogdan"}`
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/policy/restore", strings.NewReader(restoreReq)))
	if rec.Code != http.StatusOK {
		t.Fatalf("restore status = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/agents/agent:billing", nil))
	var report agentReport
	if err := json.NewDecoder(rec.Body).Decode(&report); err != nil {
		t.Fatalf("decode response body: %v", err)
	}
	if report.EffectiveState != identity.StateActive {
		t.Fatalf("EffectiveState = %q after restore, want active", report.EffectiveState)
	}
	if !report.KillSentinelChecked {
		t.Fatalf("KillSentinelChecked = false, want true")
	}

	// Restore is deliberately narrow: the credential the kill revoked
	// stays revoked, revocation is one-way, see handleRestore's own
	// doc comment. An operator has to issue a fresh one.
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/agents/agent:billing/credentials", nil))
	creds := decodeCredentials(t, rec)
	if len(creds) != 1 || creds[0].ID != cred.ID || creds[0].Status != credentials.StatusRevoked {
		t.Fatalf("got %v, want the pre-kill credential still present and still revoked, restore must not resurrect it", creds)
	}
}

func TestHandleRestore_RequiresAgentRef(t *testing.T) {
	s := newTestServer()
	mux := s.routes()

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/policy/restore", strings.NewReader(`{"operator":"bogdan"}`)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for a missing agent_ref: %s", rec.Code, rec.Body.String())
	}
}
