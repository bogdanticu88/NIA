package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bogdanticu88/nia/internal/policy"
)

func decodeGrants(t *testing.T, rec *httptest.ResponseRecorder) []policy.Grant {
	t.Helper()
	var grants []policy.Grant
	if err := json.NewDecoder(rec.Body).Decode(&grants); err != nil {
		t.Fatalf("decode response body: %v", err)
	}
	return grants
}

func registerAgentForGrants(t *testing.T, mux http.Handler, ref string) {
	t.Helper()
	body := `{"ref":"` + ref + `"}`
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/agents", strings.NewReader(body)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("register agent %s status = %d, want 201: %s", ref, rec.Code, rec.Body.String())
	}
}

func TestHandleWriteGrants_RequiresRegisteredAgent(t *testing.T) {
	s := newTestServer()
	mux := s.routes()

	rec := httptest.NewRecorder()
	body := `{"grants":[{"kind":"tool","object":"invoice.read"}]}`
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/agents/agent:billing/grants", strings.NewReader(body)))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for an unregistered agent: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleWriteGrants_RejectsEmptyGrants(t *testing.T) {
	s := newTestServer()
	mux := s.routes()
	registerAgentForGrants(t, mux, "agent:billing")

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/agents/agent:billing/grants", strings.NewReader(`{"grants":[]}`)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for empty grants: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleWriteGrants_RejectsUnknownKind(t *testing.T) {
	s := newTestServer()
	mux := s.routes()
	registerAgentForGrants(t, mux, "agent:billing")

	rec := httptest.NewRecorder()
	body := `{"grants":[{"kind":"nonsense","object":"x"}]}`
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/agents/agent:billing/grants", strings.NewReader(body)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for an unknown grant kind: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleWriteGrants_WritesAndReturnsCurrentGrants(t *testing.T) {
	s := newTestServer()
	mux := s.routes()
	registerAgentForGrants(t, mux, "agent:billing")

	rec := httptest.NewRecorder()
	body := `{"grants":[{"kind":"tool","object":"invoice.read"},{"kind":"data","object":"customer.name"}],"operator":"bogdan"}`
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/agents/agent:billing/grants", strings.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	grants := decodeGrants(t, rec)
	if len(grants) != 2 {
		t.Fatalf("got %d grants, want 2: %v", len(grants), grants)
	}
}

func TestHandleWriteGrants_WritesAuditEvent(t *testing.T) {
	s := newTestServer()
	mux := s.routes()
	registerAgentForGrants(t, mux, "agent:billing")

	body := `{"grants":[{"kind":"tool","object":"invoice.read"}],"operator":"bogdan"}`
	mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/agents/agent:billing/grants", strings.NewReader(body)))

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/agents/agent:billing/audit", nil))
	events := decodeEvents(t, rec)
	if len(events) != 2 || events[1].Action != "grant.written" {
		t.Fatalf("got %v, want agent.registered then grant.written", events)
	}
}

func TestHandleListGrants_ReturnsWhatWasWritten(t *testing.T) {
	s := newTestServer()
	mux := s.routes()
	registerAgentForGrants(t, mux, "agent:billing")

	body := `{"grants":[{"kind":"tool","object":"invoice.read"}]}`
	mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/agents/agent:billing/grants", strings.NewReader(body)))

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/agents/agent:billing/grants", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	grants := decodeGrants(t, rec)
	if len(grants) != 1 || grants[0].Object != "invoice.read" {
		t.Fatalf("got %v, want a single invoice.read tool grant", grants)
	}
}

func TestHandleDeleteGrants_RemovesOnlyWhatWasNamed(t *testing.T) {
	s := newTestServer()
	mux := s.routes()
	registerAgentForGrants(t, mux, "agent:billing")

	writeBody := `{"grants":[{"kind":"tool","object":"invoice.read"},{"kind":"tool","object":"customer.read"}]}`
	mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/agents/agent:billing/grants", strings.NewReader(writeBody)))

	deleteReq := httptest.NewRequest(http.MethodDelete, "/agents/agent:billing/grants", strings.NewReader(`{"grants":[{"kind":"tool","object":"invoice.read"}]}`))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, deleteReq)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	grants := decodeGrants(t, rec)
	if len(grants) != 1 || grants[0].Object != "customer.read" {
		t.Fatalf("got %v, want only customer.read left", grants)
	}
}
