package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bogdanticu88/nia/internal/audit"
	"github.com/bogdanticu88/nia/internal/credentials"
	"github.com/bogdanticu88/nia/internal/graph"
	"github.com/bogdanticu88/nia/internal/identity"
	"github.com/bogdanticu88/nia/internal/policy"
	"github.com/bogdanticu88/nia/internal/registry"
	"github.com/bogdanticu88/nia/internal/registry/tools"
)

// This file exercises the invariants docs/SECURITY_INVARIANTS.md states,
// the ones that are cheap to test at the HTTP handler level: the two
// small bugs closed in this pass (a discarded registry error after a
// kill, an over-broad 409 mapping on registration) and the fail-open
// postures those two fixes deliberately left alone rather than also
// flipping to fail-closed. See that doc for the reasoning behind each
// choice, this file is only the proof the behavior it describes is the
// behavior that actually runs.

var errBackendDown = fmt.Errorf("backend unavailable")

// failingSetStateRegistry wraps a real registry and makes SetState fail
// while leaving Register and Get working normally, the shape needed to
// prove a kill still succeeds even when the local registry mirror can't
// be updated afterward.
type failingSetStateRegistry struct {
	*registry.InMemoryAgentRegistry
}

func (failingSetStateRegistry) SetState(context.Context, string, identity.LifecycleState) error {
	return errBackendDown
}

// alwaysFailRegisterRegistry never succeeds a Register call, and never
// with ErrAlreadyRegistered, the shape needed to prove an unexpected
// registry failure maps to 500, not a false 409.
type alwaysFailRegisterRegistry struct {
	*registry.InMemoryAgentRegistry
}

func (alwaysFailRegisterRegistry) Register(context.Context, identity.AgentRef) error {
	return errBackendDown
}

// alwaysFailRegisterCatalog is alwaysFailRegisterRegistry's twin for
// tool registration.
type alwaysFailRegisterCatalog struct {
	*tools.InMemoryCatalog
}

func (alwaysFailRegisterCatalog) Register(context.Context, tools.Tool) error {
	return errBackendDown
}

// failingAuditStore fails every Append, the shape needed to prove a
// security-relevant action still completes and still returns success
// when the audit write alongside it fails, the fail-open posture
// docs/SECURITY_INVARIANTS.md names explicitly rather than leaves
// implied.
type failingAuditStore struct {
	inner audit.Store
}

func (f failingAuditStore) Append(context.Context, audit.Event) error {
	return errBackendDown
}

func (f failingAuditStore) Recent(ctx context.Context, n int) ([]audit.Event, error) {
	return f.inner.Recent(ctx, n)
}

func (f failingAuditStore) ForAgent(ctx context.Context, ref string) ([]audit.Event, error) {
	return f.inner.ForAgent(ctx, ref)
}

// failingGraph fails every write, the shape needed to prove
// registration, tool registration, and grant writes all still succeed
// when the identity graph they auto-populate can't be written to.
type failingGraph struct{}

func (failingGraph) AddNode(context.Context, graph.Node) error { return errBackendDown }
func (failingGraph) AddEdge(context.Context, graph.Edge) error { return errBackendDown }
func (failingGraph) Neighbors(context.Context, string, graph.EdgeKind) ([]graph.Node, error) {
	return nil, errBackendDown
}
func (failingGraph) Reachable(context.Context, string, []graph.EdgeKind) ([]graph.Node, error) {
	return nil, errBackendDown
}

func newTestServerWith(mutate func(*server)) *server {
	s := newTestServer()
	mutate(s)
	return s
}

// TestHandleKill_RegistrySetStateFails_KillStillSucceeds is the fixed
// version of the bug this pass closed: handleKill used to discard the
// SetState error outright (_ = s.agents.SetState(...)), which could
// leave the registry silently reporting an agent as active that
// Tessera/OpenFGA had actually killed. The fix logs rather than fails
// the request, this test proves the kill itself, the part that actually
// matters, still goes through and is still reported as success even
// when the registry mirror update fails.
func TestHandleKill_RegistrySetStateFails_KillStillSucceeds(t *testing.T) {
	s := newTestServer()
	if err := s.agents.Register(context.Background(), identity.AgentRef{Ref: "agent:x", Owner: "bogdan"}); err != nil {
		t.Fatalf("seed register: %v", err)
	}
	s.agents = failingSetStateRegistry{s.agents.(*registry.InMemoryAgentRegistry)}
	mux := s.routes()

	body := `{"agent_ref":"agent:x","incident":"INC-1","operator":"bogdan"}`
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/policy/kill", strings.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("kill status = %d, want 200 even though the registry mirror update failed: %s", rec.Code, rec.Body.String())
	}

	killed, err := s.pol.IsKilled(context.Background(), "agent:x")
	if err != nil {
		t.Fatalf("IsKilled: %v", err)
	}
	if !killed {
		t.Fatal("the policy client itself must report the agent as killed, that's the part a registry mirror failure must never block")
	}
}

// TestHandleRegisterAgent_UnexpectedRegistryError_Returns500NotConflict
// is the fixed version of the second bug this pass closed:
// handleRegisterAgent used to map every Register error to 409 without
// checking it was actually ErrAlreadyRegistered, harmless while the
// in-memory registry only ever returned that one error, wrong the day
// something real backs it and can fail other ways.
func TestHandleRegisterAgent_UnexpectedRegistryError_Returns500NotConflict(t *testing.T) {
	s := newTestServerWith(func(s *server) {
		s.agents = alwaysFailRegisterRegistry{s.agents.(*registry.InMemoryAgentRegistry)}
	})
	mux := s.routes()

	body := `{"ref":"agent:x","owner":"bogdan","purpose":"test"}`
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/agents", strings.NewReader(body)))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 for a registry failure that is not ErrAlreadyRegistered: %s", rec.Code, rec.Body.String())
	}
}

// TestHandleRegisterAgent_ActualDuplicate_Returns409 is the control for
// the fix above: a genuine duplicate registration must still map to 409,
// the fix narrows the mapping, it doesn't remove it.
func TestHandleRegisterAgent_ActualDuplicate_Returns409(t *testing.T) {
	s := newTestServer()
	mux := s.routes()

	body := `{"ref":"agent:x","owner":"bogdan","purpose":"test"}`
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/agents", strings.NewReader(body)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("first register status = %d, want 201: %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/agents", strings.NewReader(body)))
	if rec.Code != http.StatusConflict {
		t.Fatalf("second register status = %d, want 409 for an actual duplicate: %s", rec.Code, rec.Body.String())
	}
}

// TestHandleRegisterTool_UnexpectedCatalogError_Returns500NotConflict is
// handleRegisterTool's version of the same fix.
func TestHandleRegisterTool_UnexpectedCatalogError_Returns500NotConflict(t *testing.T) {
	s := newTestServerWith(func(s *server) {
		s.toolCat = alwaysFailRegisterCatalog{s.toolCat.(*tools.InMemoryCatalog)}
	})
	mux := s.routes()

	body := `{"name":"invoice-lookup","transport":"http","owner":"bogdan"}`
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/tools", strings.NewReader(body)))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 for a catalog failure that is not ErrAlreadyRegistered: %s", rec.Code, rec.Body.String())
	}
}

// TestHandleKill_AuditWriteFails_KillStillSucceeds proves the audit
// fail-open invariant docs/SECURITY_INVARIANTS.md names directly: an
// audit append failure must never block the security action it would
// have recorded, the action already happened, a record-keeping failure
// alongside it is a different concern.
func TestHandleKill_AuditWriteFails_KillStillSucceeds(t *testing.T) {
	s := newTestServer()
	if err := s.agents.Register(context.Background(), identity.AgentRef{Ref: "agent:x", Owner: "bogdan"}); err != nil {
		t.Fatalf("seed register: %v", err)
	}
	s.auditLog = failingAuditStore{inner: s.auditLog}
	mux := s.routes()

	body := `{"agent_ref":"agent:x","incident":"INC-1","operator":"bogdan"}`
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/policy/kill", strings.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("kill status = %d, want 200 even though the audit write failed: %s", rec.Code, rec.Body.String())
	}

	killed, err := s.pol.IsKilled(context.Background(), "agent:x")
	if err != nil {
		t.Fatalf("IsKilled: %v", err)
	}
	if !killed {
		t.Fatal("the kill itself must not be blocked by an audit write failure")
	}
}

// TestHandleRegisterAgent_GraphWriteFails_RegistrationStillSucceeds and
// TestHandleWriteGrants_GraphWriteFails_GrantStillSucceeds prove the
// same fail-open posture for the graph auto-population helpers added in
// phase 4: a graph write failing must not block the registration or
// grant it was recording a second way for traversal.
func TestHandleRegisterAgent_GraphWriteFails_RegistrationStillSucceeds(t *testing.T) {
	s := newTestServerWith(func(s *server) {
		s.graph = failingGraph{}
	})
	mux := s.routes()

	body := `{"ref":"agent:x","owner":"bogdan","purpose":"test"}`
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/agents", strings.NewReader(body)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("register status = %d, want 201 even though the graph write failed: %s", rec.Code, rec.Body.String())
	}

	got, err := s.agents.Get(context.Background(), "agent:x")
	if err != nil || got.Ref != "agent:x" {
		t.Fatalf("agent was not actually registered: got=%v err=%v", got, err)
	}
}

func TestHandleWriteGrants_GraphWriteFails_GrantStillSucceeds(t *testing.T) {
	s := newTestServerWith(func(s *server) {
		s.graph = failingGraph{}
	})
	if err := s.agents.Register(context.Background(), identity.AgentRef{Ref: "agent:x", Owner: "bogdan"}); err != nil {
		t.Fatalf("seed register: %v", err)
	}
	mux := s.routes()

	body := `{"grants":[{"kind":"tool","object":"invoice-lookup"}]}`
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/agents/agent:x/grants", strings.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("write grants status = %d, want 200 even though the graph write failed: %s", rec.Code, rec.Body.String())
	}

	allowed, err := s.pol.Check(context.Background(), "agent:x", policy.GrantForTool("invoice-lookup"))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !allowed {
		t.Fatal("the grant itself must not be blocked by a graph write failure")
	}
}

// TestHandleIssueCredential_GraphWriteFails_IssuanceStillSucceeds rounds
// out the graph fail-open coverage for the one remaining auto-population
// call site, handleIssueCredential.
func TestHandleIssueCredential_GraphWriteFails_IssuanceStillSucceeds(t *testing.T) {
	s := newTestServerWith(func(s *server) {
		s.graph = failingGraph{}
	})
	if err := s.agents.Register(context.Background(), identity.AgentRef{Ref: "agent:x", Owner: "bogdan"}); err != nil {
		t.Fatalf("seed register: %v", err)
	}
	mux := s.routes()

	body := `{"kind":"api_key"}`
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/agents/agent:x/credentials", strings.NewReader(body)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("issue status = %d, want 201 even though the graph write failed: %s", rec.Code, rec.Body.String())
	}

	var cred credentials.Credential
	if err := json.NewDecoder(rec.Body).Decode(&cred); err != nil {
		t.Fatalf("decode response body: %v", err)
	}
	if cred.AgentRef != "agent:x" {
		t.Fatalf("got credential for %q, want agent:x", cred.AgentRef)
	}
}
