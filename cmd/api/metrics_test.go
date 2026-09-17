package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bogdanticu88/nia/internal/credentials"
	"github.com/bogdanticu88/nia/internal/identity"
	"github.com/bogdanticu88/nia/internal/policy"
	"github.com/bogdanticu88/nia/internal/registry"
)

// This file proves the metrics wired into cmd/api's handlers actually
// move, one counter per result branch, plus the two gauges and the
// GET /metrics endpoint itself. Each test drives the handler through
// its normal HTTP path and reads the counter back through
// serverMetrics rather than scraping and parsing text, the text
// format itself is internal/metrics' own job to get right, see
// internal/metrics/metrics_test.go.

// failIssueCredStore fails only Issue, everything else passes through
// to the wrapped store, the shape needed to prove
// nia_credentials_issued_total counts an actual backend failure as
// "error" without disturbing the "agent must exist" check
// handleIssueCredential does before ever calling Issue.
type failIssueCredStore struct{ credentials.Store }

func (failIssueCredStore) Issue(context.Context, string, credentials.Kind, time.Duration) (credentials.Credential, string, error) {
	return credentials.Credential{}, "", errBackendDown
}

// failRevokeCredStore fails only Revoke, the shape needed to prove
// nia_credentials_revoked_total counts a backend failure as "error"
// without disturbing the Get lookup handleRevokeCredential does first.
type failRevokeCredStore struct{ credentials.Store }

func (failRevokeCredStore) Revoke(context.Context, string, string, string) error {
	return errBackendDown
}

type failWriteGrantsPolicy struct{ policy.Client }

func (failWriteGrantsPolicy) WriteGrants(context.Context, string, []policy.Grant) error {
	return errBackendDown
}

type failDeleteGrantsPolicy struct{ policy.Client }

func (failDeleteGrantsPolicy) DeleteGrants(context.Context, string, []policy.Grant) error {
	return errBackendDown
}

func TestMetrics_RegisterAgent_CountsCreatedDuplicateAndError(t *testing.T) {
	s := newTestServer()
	mux := s.routes()

	body := `{"ref":"agent:x","owner":"bogdan"}`
	mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/agents", strings.NewReader(body)))
	if got := s.metrics.registrations.Value("created"); got != 1 {
		t.Fatalf("created = %d, want 1", got)
	}

	mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/agents", strings.NewReader(body)))
	if got := s.metrics.registrations.Value("duplicate"); got != 1 {
		t.Fatalf("duplicate = %d, want 1", got)
	}

	s2 := newTestServerWith(func(s *server) {
		s.agents = alwaysFailRegisterRegistry{s.agents.(*registry.InMemoryAgentRegistry)}
	})
	mux2 := s2.routes()
	mux2.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/agents", strings.NewReader(`{"ref":"agent:y","owner":"bogdan"}`)))
	if got := s2.metrics.registrations.Value("error"); got != 1 {
		t.Fatalf("error = %d, want 1", got)
	}
}

func TestMetrics_RegisterTool_CountsCreatedAndDuplicate(t *testing.T) {
	s := newTestServer()
	mux := s.routes()

	body := `{"name":"invoice-lookup","transport":"http","owner":"bogdan"}`
	mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/tools", strings.NewReader(body)))
	if got := s.metrics.toolRegistrations.Value("created"); got != 1 {
		t.Fatalf("created = %d, want 1", got)
	}

	mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/tools", strings.NewReader(body)))
	if got := s.metrics.toolRegistrations.Value("duplicate"); got != 1 {
		t.Fatalf("duplicate = %d, want 1", got)
	}
}

func TestMetrics_IssueCredential_CountsSuccessAndError(t *testing.T) {
	s := newTestServer()
	if err := s.agents.Register(context.Background(), identity.AgentRef{Ref: "agent:x", Owner: "bogdan"}); err != nil {
		t.Fatalf("seed register: %v", err)
	}
	mux := s.routes()

	body := `{"kind":"api_key"}`
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/agents/agent:x/credentials", strings.NewReader(body)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("issue status = %d, want 201: %s", rec.Code, rec.Body.String())
	}
	if got := s.metrics.credentialsIssued.Value("success"); got != 1 {
		t.Fatalf("success = %d, want 1", got)
	}

	s2 := newTestServerWith(func(s *server) {
		s.creds = failIssueCredStore{s.creds}
	})
	if err := s2.agents.Register(context.Background(), identity.AgentRef{Ref: "agent:y", Owner: "bogdan"}); err != nil {
		t.Fatalf("seed register: %v", err)
	}
	mux2 := s2.routes()
	rec2 := httptest.NewRecorder()
	mux2.ServeHTTP(rec2, httptest.NewRequest(http.MethodPost, "/agents/agent:y/credentials", strings.NewReader(body)))
	if rec2.Code != http.StatusInternalServerError {
		t.Fatalf("issue status = %d, want 500: %s", rec2.Code, rec2.Body.String())
	}
	if got := s2.metrics.credentialsIssued.Value("error"); got != 1 {
		t.Fatalf("error = %d, want 1", got)
	}
}

func TestMetrics_RevokeCredential_CountsSuccessAndError(t *testing.T) {
	s := newTestServer()
	if err := s.agents.Register(context.Background(), identity.AgentRef{Ref: "agent:x", Owner: "bogdan"}); err != nil {
		t.Fatalf("seed register: %v", err)
	}
	cred, _, err := s.creds.Issue(context.Background(), "agent:x", credentials.KindAPIKey, 0)
	if err != nil {
		t.Fatalf("seed issue: %v", err)
	}
	mux := s.routes()

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/credentials/"+cred.ID+"/revoke", strings.NewReader(`{"revoked_by":"bogdan"}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if got := s.metrics.credentialsRevoked.Value("success"); got != 1 {
		t.Fatalf("success = %d, want 1", got)
	}

	s2 := newTestServer()
	if err := s2.agents.Register(context.Background(), identity.AgentRef{Ref: "agent:x", Owner: "bogdan"}); err != nil {
		t.Fatalf("seed register: %v", err)
	}
	cred2, _, err := s2.creds.Issue(context.Background(), "agent:x", credentials.KindAPIKey, 0)
	if err != nil {
		t.Fatalf("seed issue: %v", err)
	}
	s2.creds = failRevokeCredStore{s2.creds}
	mux2 := s2.routes()
	rec2 := httptest.NewRecorder()
	mux2.ServeHTTP(rec2, httptest.NewRequest(http.MethodPost, "/credentials/"+cred2.ID+"/revoke", strings.NewReader(`{"revoked_by":"bogdan"}`)))
	if rec2.Code != http.StatusInternalServerError {
		t.Fatalf("revoke status = %d, want 500: %s", rec2.Code, rec2.Body.String())
	}
	if got := s2.metrics.credentialsRevoked.Value("error"); got != 1 {
		t.Fatalf("error = %d, want 1", got)
	}
}

func TestMetrics_WriteGrants_CountsSuccessKilledAndError(t *testing.T) {
	s := newTestServer()
	if err := s.agents.Register(context.Background(), identity.AgentRef{Ref: "agent:x", Owner: "bogdan"}); err != nil {
		t.Fatalf("seed register: %v", err)
	}
	mux := s.routes()

	body := `{"grants":[{"kind":"tool","object":"invoice-lookup"}]}`
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/agents/agent:x/grants", strings.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("write grants status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if got := s.metrics.grantsWritten.Value("success"); got != 1 {
		t.Fatalf("success = %d, want 1", got)
	}

	killBody := `{"agent_ref":"agent:x","incident":"INC-1","operator":"bogdan"}`
	mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/policy/kill", strings.NewReader(killBody)))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/agents/agent:x/grants", strings.NewReader(body)))
	if rec.Code != http.StatusConflict {
		t.Fatalf("write grants after kill status = %d, want 409: %s", rec.Code, rec.Body.String())
	}
	if got := s.metrics.grantsWritten.Value("killed"); got != 1 {
		t.Fatalf("killed = %d, want 1", got)
	}

	s2 := newTestServerWith(func(s *server) {
		s.pol = failWriteGrantsPolicy{s.pol}
	})
	if err := s2.agents.Register(context.Background(), identity.AgentRef{Ref: "agent:y", Owner: "bogdan"}); err != nil {
		t.Fatalf("seed register: %v", err)
	}
	mux2 := s2.routes()
	rec2 := httptest.NewRecorder()
	mux2.ServeHTTP(rec2, httptest.NewRequest(http.MethodPost, "/agents/agent:y/grants", strings.NewReader(body)))
	if rec2.Code != http.StatusInternalServerError {
		t.Fatalf("write grants status = %d, want 500: %s", rec2.Code, rec2.Body.String())
	}
	if got := s2.metrics.grantsWritten.Value("error"); got != 1 {
		t.Fatalf("error = %d, want 1", got)
	}
}

func TestMetrics_DeleteGrants_CountsSuccessAndError(t *testing.T) {
	s := newTestServer()
	if err := s.agents.Register(context.Background(), identity.AgentRef{Ref: "agent:x", Owner: "bogdan"}); err != nil {
		t.Fatalf("seed register: %v", err)
	}
	mux := s.routes()

	body := `{"grants":[{"kind":"tool","object":"invoice-lookup"}]}`
	mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/agents/agent:x/grants", strings.NewReader(body)))

	req := httptest.NewRequest(http.MethodDelete, "/agents/agent:x/grants", strings.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete grants status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if got := s.metrics.grantsDeleted.Value("success"); got != 1 {
		t.Fatalf("success = %d, want 1", got)
	}

	s2 := newTestServerWith(func(s *server) {
		s.pol = failDeleteGrantsPolicy{s.pol}
	})
	if err := s2.agents.Register(context.Background(), identity.AgentRef{Ref: "agent:y", Owner: "bogdan"}); err != nil {
		t.Fatalf("seed register: %v", err)
	}
	mux2 := s2.routes()
	req2 := httptest.NewRequest(http.MethodDelete, "/agents/agent:y/grants", strings.NewReader(body))
	rec2 := httptest.NewRecorder()
	mux2.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusInternalServerError {
		t.Fatalf("delete grants status = %d, want 500: %s", rec2.Code, rec2.Body.String())
	}
	if got := s2.metrics.grantsDeleted.Value("error"); got != 1 {
		t.Fatalf("error = %d, want 1", got)
	}
}

func TestMetrics_Kill_CountsSuccess(t *testing.T) {
	s := newTestServer()
	if err := s.agents.Register(context.Background(), identity.AgentRef{Ref: "agent:x", Owner: "bogdan"}); err != nil {
		t.Fatalf("seed register: %v", err)
	}
	mux := s.routes()

	body := `{"agent_ref":"agent:x","incident":"INC-1","operator":"bogdan"}`
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/policy/kill", strings.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("kill status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if got := s.metrics.kills.Value("success"); got != 1 {
		t.Fatalf("success = %d, want 1", got)
	}
}

func TestMetrics_AuditWriteFailure_IsCounted(t *testing.T) {
	s := newTestServer()
	s.auditLog = failingAuditStore{inner: s.auditLog}
	mux := s.routes()

	mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/agents", strings.NewReader(`{"ref":"agent:x","owner":"bogdan"}`)))
	if got := s.metrics.auditWriteFailures.Value(); got != 1 {
		t.Fatalf("audit write failures = %d, want 1", got)
	}
}

func TestMetrics_GraphWriteFailure_IsCountedByOp(t *testing.T) {
	s := newTestServerWith(func(s *server) {
		s.graph = failingGraph{}
	})
	mux := s.routes()

	mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/agents", strings.NewReader(`{"ref":"agent:x","owner":"bogdan"}`)))
	if got := s.metrics.graphWriteFailures.Value("add_node"); got != 1 {
		t.Fatalf("add_node failures = %d, want 1", got)
	}

	body := `{"kind":"api_key"}`
	mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/agents/agent:x/credentials", strings.NewReader(body)))
	if got := s.metrics.graphWriteFailures.Value("add_edge"); got != 1 {
		t.Fatalf("add_edge failures = %d, want 1", got)
	}
}

func TestMetrics_GaugesReflectLiveState(t *testing.T) {
	s := newTestServer()
	mux := s.routes()

	mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/agents", strings.NewReader(`{"ref":"agent:x","owner":"bogdan"}`)))
	mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/tools", strings.NewReader(`{"name":"invoice-lookup","transport":"http","owner":"bogdan"}`)))

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("metrics status = %d, want 200", rec.Code)
	}
	out := rec.Body.String()
	if !strings.Contains(out, "nia_agents_registered 1") {
		t.Fatalf("output missing nia_agents_registered 1: %s", out)
	}
	if !strings.Contains(out, "nia_tools_registered 1") {
		t.Fatalf("output missing nia_tools_registered 1: %s", out)
	}
}

func TestMetrics_ServeHTTP_SetsContentType(t *testing.T) {
	s := newTestServer()
	mux := s.routes()

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/plain") {
		t.Fatalf("Content-Type = %q, want text/plain", ct)
	}
}

func TestHandleGetAgent_FoundAndNotFound(t *testing.T) {
	s := newTestServer()
	mux := s.routes()

	mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/agents", strings.NewReader(`{"ref":"agent:x","owner":"bogdan","purpose":"test"}`)))

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/agents/agent:x", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("get agent status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var agent identity.AgentRef
	if err := json.NewDecoder(rec.Body).Decode(&agent); err != nil {
		t.Fatalf("decode response body: %v", err)
	}
	if agent.Ref != "agent:x" {
		t.Fatalf("Ref = %q, want agent:x", agent.Ref)
	}

	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/agents/agent:does-not-exist", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("get missing agent status = %d, want 404: %s", rec.Code, rec.Body.String())
	}
}
