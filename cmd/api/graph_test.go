package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bogdanticu88/nia/internal/graph"
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
