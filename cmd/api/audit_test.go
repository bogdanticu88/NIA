package main

import (
	"context"
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

func TestHandleVerifyAudit_UntamperedTrail_ReportsOK(t *testing.T) {
	s := newTestServer()
	mux := s.routes()

	mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/agents", strings.NewReader(`{"ref":"agent:billing","owner":"bogdan"}`)))
	mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/policy/kill", strings.NewReader(`{"agent_ref":"agent:billing","incident":"INC-1","operator":"bogdan"}`)))

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/audit/verify", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	var result audit.VerifyResult
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !result.OK {
		t.Fatalf("got %+v, want OK for an untampered trail", result)
	}
	if result.Checked != 2 {
		t.Fatalf("Checked = %d, want 2 (register + kill)", result.Checked)
	}
	if len(result.Breaks) != 0 {
		t.Fatalf("Breaks = %v, want none", result.Breaks)
	}
}

// tamperedChainStore wraps a real *audit.InMemorySink, delegating
// every Store method to it unchanged (Append, Recent, ForAgent are all
// promoted from the embedded field) except Chain, which is overridden
// to mutate whatever the real sink reports before returning it. This
// is how TestHandleVerifyAudit_TamperedTrail_ReportsBreaks simulates a
// database-level tamper from outside the audit package, where
// InMemorySink's internal storage is unexported and genuinely not
// reachable directly: audit events are never editable through the real
// API by design, so there is no legitimate HTTP path to corrupt one,
// this stands in for an attacker with direct store access instead.
type tamperedChainStore struct {
	*audit.InMemorySink
	mutate func([]audit.ChainedEvent)
}

func (t tamperedChainStore) Chain(ctx context.Context) (audit.Chain, error) {
	chain, err := t.InMemorySink.Chain(ctx)
	if err != nil {
		return audit.Chain{}, err
	}
	t.mutate(chain.Events)
	return chain, nil
}

func TestHandleVerifyAudit_TamperedTrail_ReportsBreaks(t *testing.T) {
	s := newTestServer()
	mux := s.routes()

	mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/agents", strings.NewReader(`{"ref":"agent:billing","owner":"bogdan"}`)))

	realSink, ok := s.auditLog.(*audit.InMemorySink)
	if !ok {
		t.Fatalf("newTestServer's auditLog is %T, want *audit.InMemorySink", s.auditLog)
	}
	s.auditLog = tamperedChainStore{
		InMemorySink: realSink,
		mutate: func(events []audit.ChainedEvent) {
			if len(events) == 0 {
				t.Fatal("test setup broken: expected at least one event to tamper with")
			}
			events[0].Detail = "tampered via direct store access"
		},
	}

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/audit/verify", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (verify itself succeeded, it just found a problem): %s", rec.Code, rec.Body.String())
	}

	var result audit.VerifyResult
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result.OK {
		t.Fatal("got OK=true, want the tampered event to be caught over the HTTP endpoint")
	}
	if len(result.Breaks) == 0 {
		t.Fatal("got no breaks, want at least one naming the tampered event")
	}
}

func TestHandleVerifyAudit_BackendWithoutChainSupport_501(t *testing.T) {
	s := newTestServer()
	s.auditLog = nonChainedStore{}
	mux := s.routes()

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/audit/verify", nil))
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501 when the configured audit backend doesn't implement audit.Chained: %s", rec.Code, rec.Body.String())
	}
}

// nonChainedStore is a minimal audit.Store that deliberately does not
// implement audit.Chained, proving handleVerifyAudit's type assertion
// fails closed (501) rather than panicking if a future Sink
// implementation doesn't support chain verification.
type nonChainedStore struct{}

func (nonChainedStore) Append(context.Context, audit.Event) error               { return nil }
func (nonChainedStore) Recent(context.Context, int) ([]audit.Event, error)      { return nil, nil }
func (nonChainedStore) ForAgent(context.Context, string) ([]audit.Event, error) { return nil, nil }

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
