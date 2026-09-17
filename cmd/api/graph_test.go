package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bogdanticu88/nia/internal/graph"
	"github.com/bogdanticu88/nia/internal/policy"
	"github.com/bogdanticu88/nia/internal/sensitivity"
)

func decodeNode(t *testing.T, rec *httptest.ResponseRecorder) graph.Node {
	t.Helper()
	var n graph.Node
	if err := json.NewDecoder(rec.Body).Decode(&n); err != nil {
		t.Fatalf("decode response body: %v", err)
	}
	return n
}

func decodeNodes(t *testing.T, rec *httptest.ResponseRecorder) []graph.Node {
	t.Helper()
	var list []graph.Node
	if err := json.NewDecoder(rec.Body).Decode(&list); err != nil {
		t.Fatalf("decode response body: %v", err)
	}
	return list
}

func addNode(t *testing.T, mux http.Handler, id, kind string) {
	t.Helper()
	body := `{"id":"` + id + `","kind":"` + kind + `"}`
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/graph/nodes", strings.NewReader(body)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("add node %s status = %d, want 201: %s", id, rec.Code, rec.Body.String())
	}
}

func addEdge(t *testing.T, mux http.Handler, from, to, kind string) {
	t.Helper()
	body := `{"from":"` + from + `","to":"` + to + `","kind":"` + kind + `"}`
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/graph/edges", strings.NewReader(body)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("add edge %s->%s status = %d, want 201: %s", from, to, rec.Code, rec.Body.String())
	}
}

func TestHandleAddGraphNode_RejectsUnknownKind(t *testing.T) {
	s := newTestServer()
	mux := s.routes()

	rec := httptest.NewRecorder()
	body := `{"id":"agent:billing","kind":"robot"}`
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/graph/nodes", strings.NewReader(body)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for an unknown node kind: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleAddGraphNode_RejectsMissingID(t *testing.T) {
	s := newTestServer()
	mux := s.routes()

	rec := httptest.NewRecorder()
	body := `{"kind":"agent"}`
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/graph/nodes", strings.NewReader(body)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for a missing id: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleAddGraphNode_Adds(t *testing.T) {
	s := newTestServer()
	mux := s.routes()

	rec := httptest.NewRecorder()
	body := `{"id":"agent:billing","kind":"agent"}`
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/graph/nodes", strings.NewReader(body)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", rec.Code, rec.Body.String())
	}
	n := decodeNode(t, rec)
	if n.ID != "agent:billing" || n.Kind != graph.NodeAgent {
		t.Fatalf("got %+v, want agent:billing/agent", n)
	}
}

func TestHandleAddGraphEdge_RejectsUnknownKind(t *testing.T) {
	s := newTestServer()
	mux := s.routes()

	rec := httptest.NewRecorder()
	body := `{"from":"agent:a","to":"agent:b","kind":"knows"}`
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/graph/edges", strings.NewReader(body)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for an unknown edge kind: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleAddGraphEdge_RejectsMissingEndpoints(t *testing.T) {
	s := newTestServer()
	mux := s.routes()

	rec := httptest.NewRecorder()
	body := `{"to":"agent:b","kind":"trusts"}`
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/graph/edges", strings.NewReader(body)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for a missing from: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleGraphNeighbors_RequiresKind(t *testing.T) {
	s := newTestServer()
	mux := s.routes()
	addNode(t, mux, "agent:a", "agent")

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/graph/agent:a/neighbors", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 without a kind query param: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleGraphNeighbors_ReturnsOneHop(t *testing.T) {
	s := newTestServer()
	mux := s.routes()

	addNode(t, mux, "agent:a", "agent")
	addNode(t, mux, "agent:b", "agent")
	addNode(t, mux, "agent:c", "agent")
	addEdge(t, mux, "agent:a", "agent:b", "trusts")
	addEdge(t, mux, "agent:b", "agent:c", "trusts")

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/graph/agent:a/neighbors?kind=trusts", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	nodes := decodeNodes(t, rec)
	if len(nodes) != 1 || nodes[0].ID != "agent:b" {
		t.Fatalf("got %+v, want only agent:b, one hop out", nodes)
	}
}

// TestHandleGraphReachable_FollowsDelegationChains is the same
// blast-radius scenario internal/graph/graph_test.go exercises directly
// against InMemoryGraph, run here over the HTTP layer instead.
func TestHandleGraphReachable_FollowsDelegationChains(t *testing.T) {
	s := newTestServer()
	mux := s.routes()

	addNode(t, mux, "agent:a", "agent")
	addNode(t, mux, "agent:b", "agent")
	addNode(t, mux, "agent:c", "agent")
	addNode(t, mux, "tool:invoice-api", "tool")
	addEdge(t, mux, "agent:a", "agent:b", "delegates_to")
	addEdge(t, mux, "agent:b", "agent:c", "delegates_to")
	addEdge(t, mux, "agent:c", "tool:invoice-api", "grants")

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/graph/agent:a/reachable?kinds=delegates_to,grants", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	ids := map[string]bool{}
	for _, n := range decodeNodes(t, rec) {
		ids[n.ID] = true
	}
	for _, want := range []string{"agent:b", "agent:c", "tool:invoice-api"} {
		if !ids[want] {
			t.Fatalf("expected %s to be reachable from agent:a, got %v", want, ids)
		}
	}
}

func TestHandleGraphReachable_DefaultsToAllEdgeKindsWhenKindsOmitted(t *testing.T) {
	s := newTestServer()
	mux := s.routes()

	addNode(t, mux, "human:bogdan", "human")
	addNode(t, mux, "agent:a", "agent")
	addNode(t, mux, "tool:invoice-api", "tool")
	addEdge(t, mux, "human:bogdan", "agent:a", "owns")
	addEdge(t, mux, "agent:a", "tool:invoice-api", "grants")

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/graph/human:bogdan/reachable", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	ids := map[string]bool{}
	for _, n := range decodeNodes(t, rec) {
		ids[n.ID] = true
	}
	for _, want := range []string{"agent:a", "tool:invoice-api"} {
		if !ids[want] {
			t.Fatalf("expected %s reachable across owns and grants with -kinds omitted, got %v", want, ids)
		}
	}
}

func TestHandleGraphReachable_RejectsUnknownKind(t *testing.T) {
	s := newTestServer()
	mux := s.routes()
	addNode(t, mux, "agent:a", "agent")

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/graph/agent:a/reachable?kinds=trusts,knows", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for an unknown kind in -kinds: %s", rec.Code, rec.Body.String())
	}
}

// TestAgentRegistration_AutoAddsGraphNode is the auto-population this
// phase added: registering an agent through /agents, not /graph/nodes,
// should already give it a graph node, so a blast-radius query on a
// freshly registered agent isn't empty just because nobody separately
// hand-built it into the graph.
func TestAgentRegistration_AutoAddsGraphNode(t *testing.T) {
	s := newTestServer()
	mux := s.routes()
	registerAgentForGrants(t, mux, "agent:billing")

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/graph/agent:billing/neighbors?kind=grants", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, the node should exist even with no edges yet: %s", rec.Code, rec.Body.String())
	}
}

func TestToolRegistration_AutoAddsGraphNode(t *testing.T) {
	s := newTestServer()
	mux := s.routes()

	body := `{"name":"invoice.read","risk_class":"read_only"}`
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/tools", strings.NewReader(body)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("register tool status = %d, want 201: %s", rec.Code, rec.Body.String())
	}

	reachRec := httptest.NewRecorder()
	mux.ServeHTTP(reachRec, httptest.NewRequest(http.MethodGet, "/graph/invoice.read/neighbors?kind=grants", nil))
	if reachRec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, the tool node should exist: %s", reachRec.Code, reachRec.Body.String())
	}
}

// TestWriteGrants_AutoAddsGrantsEdge is the piece that makes a
// blast-radius query actually mean something without an operator
// hand-building the graph: writing a tool or data grant through
// /agents/{ref}/grants should add both nodes (if they don't already
// exist) and a grants edge from the agent to the object.
func TestWriteGrants_AutoAddsGrantsEdge(t *testing.T) {
	s := newTestServer()
	mux := s.routes()
	registerAgentForGrants(t, mux, "agent:billing")

	body := `{"grants":[{"kind":"tool","object":"invoice.read"},{"kind":"data","object":"customer.ssn"}]}`
	writeRec := httptest.NewRecorder()
	mux.ServeHTTP(writeRec, httptest.NewRequest(http.MethodPost, "/agents/agent:billing/grants", strings.NewReader(body)))
	if writeRec.Code != http.StatusOK {
		t.Fatalf("write grants status = %d, want 200: %s", writeRec.Code, writeRec.Body.String())
	}

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/graph/agent:billing/neighbors?kind=grants", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	ids := map[string]bool{}
	for _, n := range decodeNodes(t, rec) {
		ids[n.ID] = true
	}
	if !ids["invoice.read"] || !ids["customer.ssn"] {
		t.Fatalf("got %v, want both invoice.read and customer.ssn reachable via a grants edge", ids)
	}
}

func TestWriteGrants_APIGroupAndEndpointGrantsDoNotAddEdges(t *testing.T) {
	s := newTestServer()
	mux := s.routes()
	registerAgentForGrants(t, mux, "agent:billing")

	body := `{"grants":[{"kind":"api_group","group":"invoices"},{"kind":"endpoint","method":"GET","path":"/invoices"}]}`
	writeRec := httptest.NewRecorder()
	mux.ServeHTTP(writeRec, httptest.NewRequest(http.MethodPost, "/agents/agent:billing/grants", strings.NewReader(body)))
	if writeRec.Code != http.StatusOK {
		t.Fatalf("write grants status = %d, want 200: %s", writeRec.Code, writeRec.Body.String())
	}

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/graph/agent:billing/neighbors?kind=grants", nil))
	nodes := decodeNodes(t, rec)
	if len(nodes) != 0 {
		t.Fatalf("got %v, want no grants edges from api_group/endpoint grants, neither has a natural graph node", nodes)
	}
}

func TestIssueCredential_AutoAddsBoundToEdge(t *testing.T) {
	s := newTestServer()
	mux := s.routes()
	registerAgentForGrants(t, mux, "agent:billing")

	body := `{"kind":"api_key"}`
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/agents/agent:billing/credentials", strings.NewReader(body)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("issue credential status = %d, want 201: %s", rec.Code, rec.Body.String())
	}
	var cred struct {
		ID string `json:"ID"`
	}
	json.Unmarshal(rec.Body.Bytes(), &cred)
	if cred.ID == "" {
		t.Fatal("could not read the issued credential's id back")
	}

	neighRec := httptest.NewRecorder()
	mux.ServeHTTP(neighRec, httptest.NewRequest(http.MethodGet, "/graph/"+cred.ID+"/neighbors?kind=bound_to", nil))
	nodes := decodeNodes(t, neighRec)
	if len(nodes) != 1 || nodes[0].ID != "agent:billing" {
		t.Fatalf("got %v, want the credential's bound_to edge pointing at agent:billing", nodes)
	}
}

func decodeBlastRadius(t *testing.T, rec *httptest.ResponseRecorder) blastRadius {
	t.Helper()
	var br blastRadius
	if err := json.Unmarshal(rec.Body.Bytes(), &br); err != nil {
		t.Fatalf("decode response body: %v", err)
	}
	return br
}

func TestHandleBlastRadius_EmptyGraph_LowSeverity(t *testing.T) {
	s := newTestServer()
	mux := s.routes()
	addNode(t, mux, "agent:a", "agent")

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/graph/agent:a/blast-radius", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	br := decodeBlastRadius(t, rec)
	if br.Total != 0 || br.Severity != "LOW" {
		t.Fatalf("got %+v, want Total=0 Severity=LOW for a node with nothing reachable", br)
	}
}

func TestHandleBlastRadius_CountsByKindAndControllableSeverity(t *testing.T) {
	s := newTestServer()
	mux := s.routes()
	addNode(t, mux, "agent:a", "agent")
	addNode(t, mux, "agent:b", "agent")
	addNode(t, mux, "tool:invoice-api", "tool")
	addEdge(t, mux, "agent:a", "agent:b", "trusts")
	addEdge(t, mux, "agent:a", "tool:invoice-api", "grants")

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/graph/agent:a/blast-radius", nil))
	br := decodeBlastRadius(t, rec)
	if br.Total != 2 {
		t.Fatalf("Total = %d, want 2", br.Total)
	}
	if br.ByKind[graph.NodeAgent] != 1 || br.ByKind[graph.NodeTool] != 1 {
		t.Fatalf("ByKind = %v, want agent:1 tool:1", br.ByKind)
	}
	if br.Severity != "MEDIUM" {
		t.Fatalf("Severity = %q, want MEDIUM, at least one reachable agent/tool but nothing sensitive", br.Severity)
	}
}

func TestHandleBlastRadius_UnknownKind400(t *testing.T) {
	s := newTestServer()
	mux := s.routes()
	addNode(t, mux, "agent:a", "agent")

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/graph/agent:a/blast-radius?kinds=nonsense", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for an unknown edge kind", rec.Code)
	}
}

// fakeClassifier lets a test force specific resources to classify at a
// given sensitivity level without depending on internal/sensitivity's
// own rule-file parsing.
type fakeClassifier map[string]sensitivity.Level

func (f fakeClassifier) Classify(object string) sensitivity.Level {
	if lvl, ok := f[object]; ok {
		return lvl
	}
	return sensitivity.Public
}

func TestHandleBlastRadius_CriticalResourceMeansHighSeverity(t *testing.T) {
	s := newTestServer()
	s.sensitive = fakeClassifier{"customer.ssn": sensitivity.Critical}
	mux := s.routes()
	addNode(t, mux, "agent:a", "agent")
	addNode(t, mux, "customer.ssn", "data")
	addEdge(t, mux, "agent:a", "customer.ssn", "grants")

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/graph/agent:a/blast-radius", nil))
	br := decodeBlastRadius(t, rec)
	if br.Severity != "HIGH" {
		t.Fatalf("Severity = %q, want HIGH, a critical resource is reachable", br.Severity)
	}
	if len(br.CriticalResources) != 1 || br.CriticalResources[0] != "customer.ssn" {
		t.Fatalf("CriticalResources = %v, want [customer.ssn]", br.CriticalResources)
	}
}

func TestHandleBlastRadius_SensitiveResourceMeansMediumSeverity(t *testing.T) {
	s := newTestServer()
	s.sensitive = fakeClassifier{"customer.email": sensitivity.Sensitive}
	mux := s.routes()
	addNode(t, mux, "agent:a", "agent")
	addNode(t, mux, "customer.email", "data")
	addEdge(t, mux, "agent:a", "customer.email", "grants")

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/graph/agent:a/blast-radius", nil))
	br := decodeBlastRadius(t, rec)
	if br.Severity != "MEDIUM" {
		t.Fatalf("Severity = %q, want MEDIUM, a sensitive (not critical) resource is reachable", br.Severity)
	}
	if len(br.SensitiveResources) != 1 || br.SensitiveResources[0] != "customer.email" {
		t.Fatalf("SensitiveResources = %v, want [customer.email]", br.SensitiveResources)
	}
}

// TestGraphEdgeSurvivesGrantDeletion_ButPolicyCheckReflectsCurrentTruth
// is item 6's test: it makes the identity graph's chosen lifecycle
// model (internal/graph's package doc comment, docs/ARCHITECTURE.md's
// "The identity graph" section) concrete rather than only documented.
// The graph is historical and append-only, deleting a grant leaves the
// grants edge it added in place, while internal/policy, the live
// OpenFGA-backed authorization source, reflects the deletion
// immediately. Both halves matter together: if this test only checked
// that Check goes from allowed to denied, it wouldn't prove the graph
// is actually a superset rather than incidentally correct; if it only
// checked the edge survives, it wouldn't prove live authorization is
// still safe to rely on. A consumer who reads graph reachability as
// "currently granted" would get exactly this scenario wrong.
func TestGraphEdgeSurvivesGrantDeletion_ButPolicyCheckReflectsCurrentTruth(t *testing.T) {
	s := newTestServer()
	mux := s.routes()
	registerAgentForGrants(t, mux, "agent:billing")

	writeBody := `{"grants":[{"kind":"tool","object":"invoice.read"}]}`
	mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/agents/agent:billing/grants", strings.NewReader(writeBody)))

	ctx := context.Background()
	allowed, err := s.pol.Check(ctx, "agent:billing", policy.GrantForTool("invoice.read"))
	if err != nil {
		t.Fatalf("Check before delete: %v", err)
	}
	if !allowed {
		t.Fatal("expected the grant to be live-authorized right after it was written")
	}

	deleteReq := httptest.NewRequest(http.MethodDelete, "/agents/agent:billing/grants", strings.NewReader(`{"grants":[{"kind":"tool","object":"invoice.read"}]}`))
	deleteRec := httptest.NewRecorder()
	mux.ServeHTTP(deleteRec, deleteReq)
	if deleteRec.Code != http.StatusOK {
		t.Fatalf("delete grants status = %d, want 200: %s", deleteRec.Code, deleteRec.Body.String())
	}

	// internal/policy: the live source of truth. Must reflect the
	// deletion immediately, this is what every real authorization
	// decision in this codebase actually checks against.
	allowed, err = s.pol.Check(ctx, "agent:billing", policy.GrantForTool("invoice.read"))
	if err != nil {
		t.Fatalf("Check after delete: %v", err)
	}
	if allowed {
		t.Fatal("expected the grant to be denied after deletion, internal/policy must be the live authorization source of truth")
	}

	// internal/graph: historical, append-only. The edge this grant
	// wrote when it was created must still be there, that's the
	// deliberately chosen model, not a bug.
	neighRec := httptest.NewRecorder()
	mux.ServeHTTP(neighRec, httptest.NewRequest(http.MethodGet, "/graph/agent:billing/neighbors?kind=grants", nil))
	found := false
	for _, n := range decodeNodes(t, neighRec) {
		if n.ID == "invoice.read" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected the grants edge to survive the grant's deletion, the graph is historical and append-only by design, this is the intended model, not a stale-safe mirror of current authorization")
	}
}

func TestHandleBlastRadius_FiveOrMoreControllableNodesMeansHighSeverity(t *testing.T) {
	s := newTestServer()
	mux := s.routes()
	addNode(t, mux, "agent:a", "agent")
	for i := 0; i < 5; i++ {
		id := "tool:t" + string(rune('0'+i))
		addNode(t, mux, id, "tool")
		addEdge(t, mux, "agent:a", id, "grants")
	}

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/graph/agent:a/blast-radius", nil))
	br := decodeBlastRadius(t, rec)
	if br.Severity != "HIGH" {
		t.Fatalf("Severity = %q, want HIGH, five reachable tools even with nothing classified sensitive", br.Severity)
	}
}
