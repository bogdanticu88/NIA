package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bogdanticu88/nia/internal/credentials"
)

func decodeCredential(t *testing.T, rec *httptest.ResponseRecorder) credentials.Credential {
	t.Helper()
	var cred credentials.Credential
	if err := json.NewDecoder(rec.Body).Decode(&cred); err != nil {
		t.Fatalf("decode response body: %v", err)
	}
	return cred
}

func decodeCredentials(t *testing.T, rec *httptest.ResponseRecorder) []credentials.Credential {
	t.Helper()
	var creds []credentials.Credential
	if err := json.NewDecoder(rec.Body).Decode(&creds); err != nil {
		t.Fatalf("decode response body: %v", err)
	}
	return creds
}

func TestHandleIssueCredential_RequiresRegisteredAgent(t *testing.T) {
	s := newTestServer()
	mux := s.routes()

	rec := httptest.NewRecorder()
	body := `{"kind":"api_key"}`
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/agents/agent:ghost/credentials", strings.NewReader(body)))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for an unregistered agent: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleIssueCredential_RejectsUnknownKind(t *testing.T) {
	s := newTestServer()
	mux := s.routes()

	mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/agents", strings.NewReader(`{"ref":"agent:billing","owner":"bogdan"}`)))

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/agents/agent:billing/credentials", strings.NewReader(`{"kind":"smart_card"}`)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for an unknown kind: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleIssueCredential_WritesAuditEvent(t *testing.T) {
	s := newTestServer()
	mux := s.routes()

	mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/agents", strings.NewReader(`{"ref":"agent:billing","owner":"bogdan"}`)))

	rec := httptest.NewRecorder()
	issueReq := `{"kind":"api_key","operator":"bogdan"}`
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/agents/agent:billing/credentials", strings.NewReader(issueReq)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("issue status = %d, want 201: %s", rec.Code, rec.Body.String())
	}
	cred := decodeCredential(t, rec)
	if cred.ID == "" || cred.AgentRef != "agent:billing" || cred.Kind != credentials.KindAPIKey {
		t.Fatalf("got %+v, want a populated api_key credential for agent:billing", cred)
	}
	if cred.Status != credentials.StatusActive {
		t.Fatalf("Status = %q, want active", cred.Status)
	}

	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/agents/agent:billing/audit", nil))
	events := decodeEvents(t, rec)
	if len(events) != 2 || events[1].Action != "credential.issued" {
		t.Fatalf("got %v, want agent.registered followed by credential.issued", events)
	}
}

func TestHandleListCredentials_OnlyReturnsThatAgents(t *testing.T) {
	s := newTestServer()
	mux := s.routes()

	for _, ref := range []string{"agent:billing", "agent:reporting"} {
		mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/agents", strings.NewReader(`{"ref":"`+ref+`","owner":"bogdan"}`)))
		mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/agents/"+ref+"/credentials", strings.NewReader(`{"kind":"api_key"}`)))
	}

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/agents/agent:billing/credentials", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	creds := decodeCredentials(t, rec)
	if len(creds) != 1 || creds[0].AgentRef != "agent:billing" {
		t.Fatalf("got %v, want exactly one credential for agent:billing", creds)
	}
}

func TestHandleRevokeCredential_WritesAuditEventAndUpdatesStatus(t *testing.T) {
	s := newTestServer()
	mux := s.routes()

	mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/agents", strings.NewReader(`{"ref":"agent:billing","owner":"bogdan"}`)))

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/agents/agent:billing/credentials", strings.NewReader(`{"kind":"api_key"}`)))
	cred := decodeCredential(t, rec)

	rec = httptest.NewRecorder()
	revokeReq := `{"revoked_by":"bogdan","reason":"key leaked in a log"}`
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/credentials/"+cred.ID+"/revoke", strings.NewReader(revokeReq)))
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	updated := decodeCredential(t, rec)
	if updated.Status != credentials.StatusRevoked || updated.RevokedBy != "bogdan" {
		t.Fatalf("got %+v, want a revoked credential attributed to bogdan", updated)
	}

	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/agents/agent:billing/audit", nil))
	events := decodeEvents(t, rec)
	if len(events) != 3 || events[2].Action != "credential.revoked" {
		t.Fatalf("got %v, want registered, issued, then credential.revoked", events)
	}
}

func TestHandleRevokeCredential_NotFound(t *testing.T) {
	s := newTestServer()
	mux := s.routes()

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/credentials/does-not-exist/revoke", strings.NewReader(`{"revoked_by":"bogdan"}`)))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for an unknown credential id: %s", rec.Code, rec.Body.String())
	}
}
