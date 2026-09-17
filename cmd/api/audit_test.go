package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bogdanticu88/nia/internal/audit"
	"github.com/bogdanticu88/nia/internal/credentials"
	"github.com/bogdanticu88/nia/internal/graph"
	"github.com/bogdanticu88/nia/internal/metrics"
	"github.com/bogdanticu88/nia/internal/policy"
	"github.com/bogdanticu88/nia/internal/registry"
	"github.com/bogdanticu88/nia/internal/registry/tools"
)

func newTestServer() *server {
	s := &server{
		agents:   registry.NewInMemoryAgentRegistry(),
		toolCat:  tools.NewInMemoryCatalog(),
		creds:    credentials.NewInMemoryStore(),
		pol:      policy.NewInMemoryClient(),
		auditLog: audit.NewInMemorySink(10_000),
		graph:    graph.NewInMemoryGraph(),
	}
	reg := metrics.NewRegistry()
	s.metrics = newServerMetrics(reg, s)
	s.metricsReg = reg
	return s
}

func decodeEvents(t *testing.T, rec *httptest.ResponseRecorder) []audit.Event {
	t.Helper()
	var events []audit.Event
	if err := json.NewDecoder(rec.Body).Decode(&events); err != nil {
		t.Fatalf("decode response body: %v", err)
	}
	return events
}

func TestHandleRegisterAgent_WritesAuditEvent(t *testing.T) {
	s := newTestServer()
	mux := s.routes()

	body := `{"ref":"agent:billing-reconciler","owner":"bogdan","purpose":"reconciles invoices"}`
	req := httptest.NewRequest(http.MethodPost, "/agents", strings.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("register status = %d, want 201: %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/agents/agent:billing-reconciler/audit", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("agent audit status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	events := decodeEvents(t, rec)
	if len(events) != 1 || events[0].Action != "agent.registered" {
		t.Fatalf("got %v, want exactly one agent.registered event", events)
	}
}

func TestHandleAgentAudit_DoesNotLeakOtherAgents(t *testing.T) {
	s := newTestServer()
	mux := s.routes()

	for _, ref := range []string{"agent:billing", "agent:reporting"} {
		body := `{"ref":"` + ref + `","owner":"bogdan"}`
		mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/agents", strings.NewReader(body)))
	}

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/agents/agent:billing/audit", nil))
	events := decodeEvents(t, rec)
	if len(events) != 1 || events[0].AgentRef != "agent:billing" {
		t.Fatalf("got %v, want exactly one event for agent:billing", events)
	}
}

func TestHandleRecentAudit_DefaultAndExplicitLimit(t *testing.T) {
	s := newTestServer()
	mux := s.routes()

	for i := 0; i < 5; i++ {
		body := `{"ref":"agent:test` + string(rune('a'+i)) + `","owner":"bogdan"}`
		mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/agents", strings.NewReader(body)))
	}

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/audit?limit=3", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	events := decodeEvents(t, rec)
	if len(events) != 3 {
		t.Fatalf("got %d events with limit=3, want 3", len(events))
	}
}

func TestHandleRecentAudit_RejectsBadLimit(t *testing.T) {
	s := newTestServer()
	mux := s.routes()

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/audit?limit=not-a-number", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for a non-numeric limit", rec.Code)
	}
}

func TestHandleKill_WritesAuditEvent(t *testing.T) {
	s := newTestServer()
	mux := s.routes()

	mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/agents", strings.NewReader(`{"ref":"agent:billing","owner":"bogdan"}`)))

	rec := httptest.NewRecorder()
	killReq := `{"agent_ref":"agent:billing","incident":"INC-001","operator":"bogdan"}`
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/policy/kill", strings.NewReader(killReq)))
	if rec.Code != http.StatusOK {
		t.Fatalf("kill status = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/agents/agent:billing/audit", nil))
	events := decodeEvents(t, rec)
	if len(events) != 2 {
		t.Fatalf("got %d events, want 2 (registered + killed): %v", len(events), events)
	}
	if events[0].Action != "agent.registered" || events[1].Action != "agent.killed" {
		t.Fatalf("wrong event order: %v", events)
	}
	if events[1].Incident != "INC-001" {
		t.Fatalf("Incident = %q, want INC-001", events[1].Incident)
	}
}
