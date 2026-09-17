// Package graph is the identity graph: humans, agents, tools, and data
// resources as nodes, ownership/trust/delegation/grant relationships as
// edges. OpenFGA (via internal/policy) answers "can X do Y right now."
// This package answers a different question: "everything X could
// reach, directly or transitively," which is what incident response
// and blast-radius analysis actually need, and which a live
// point-in-time authorization check can't give you on its own.
//
// What this package is not, stated plainly because it's easy to
// assume otherwise: it is not a live mirror of current authorization,
// and it is not meant to become one. There is no edge-removal
// operation on Graph, on purpose. When a grant is deleted through
// internal/policy, the corresponding grants edge added when that
// grant was written stays in the graph. This is a deliberate choice
// (call it model 2 of the two the graph could have followed: either
// "current relationships only, with edge removal," or "historical,
// append-only, a superset of current authorization"), not an
// oversight waiting to be closed. The graph exists to answer "what
// has this identity ever been connected to, and what could that
// chain reach," a question incident response and onboarding review
// actually want answered even after some of those relationships have
// since been revoked, an operator reviewing a compromised agent wants
// to see everything it was ever granted, not just what remains today.
// internal/policy (OpenFGA/Tessera, via policy.Client) is the only
// source of truth for what's authorized right now, always. Reachable
// and Neighbors describe discovered relationships, not current
// permission, and no caller, in this codebase or outside it, should
// treat a node showing up in a Reachable result as proof that node is
// still granted access today, GET /agents/{ref}/grants (ListGrants)
// or a direct Check is what answers that. See cmd/api/main.go's
// graphAddGrantEdges and handleDeleteGrants for where this shows up
// concretely, cmd/api/graph_test.go's
// TestGraphEdgeSurvivesGrantDeletion_ButPolicyCheckReflectsCurrentTruth
// for a test that exercises the distinction end to end, and
// docs/ARCHITECTURE.md's "The identity graph" section and
// docs/SECURITY_INVARIANTS.md for the same statement made at the
// documentation layer.
package graph

import (
	"context"
	"sync"
)

// NodeKind distinguishes what a node represents.
type NodeKind string

const (
	NodeHuman      NodeKind = "human"
	NodeAgent      NodeKind = "agent"
	NodeTool       NodeKind = "tool"
	NodeData       NodeKind = "data"
	NodeCredential NodeKind = "credential"
)

// EdgeKind is the relationship an edge represents. Named to match the
// vocabulary used elsewhere in NIA and in Tessera's own tuple model
// (member, grants) so a grant recorded in internal/policy and an edge
// recorded here describe the same fact two different ways: one for live
// checks, one for graph traversal.
type EdgeKind string

const (
	EdgeOwns        EdgeKind = "owns"         // Human -> Agent
	EdgeDelegatesTo EdgeKind = "delegates_to" // Agent -> Agent, time-bounded
	EdgeTrusts      EdgeKind = "trusts"       // Agent -> Agent
	EdgeMemberOf    EdgeKind = "member_of"    // Agent -> group
	EdgeGrants      EdgeKind = "grants"       // Agent -> Tool | Data
	EdgeBoundTo     EdgeKind = "bound_to"     // Credential -> Agent
)

// Node is one entity in the graph.
type Node struct {
	ID   string
	Kind NodeKind
}

// Edge is a directed relationship between two nodes.
type Edge struct {
	From string
	To   string
	Kind EdgeKind
}

// Graph is the identity graph store: add nodes and edges, and traverse
// for blast-radius queries. Deliberately append-only, see this
// package's doc comment: there is no RemoveEdge, adding one would
// change what this store is for.
type Graph interface {
	AddNode(ctx context.Context, n Node) error
	AddEdge(ctx context.Context, e Edge) error
	Neighbors(ctx context.Context, id string, kind EdgeKind) ([]Node, error)
	// Reachable returns every node reachable from id by following edges
	// of any of the given kinds, transitively. This is the blast-radius
	// query: "if this agent is compromised, what can it reach."
	Reachable(ctx context.Context, id string, kinds []EdgeKind) ([]Node, error)
}

// InMemoryGraph is the reference implementation: an adjacency list, no
// external graph database. Fine for the scale of a single deployment's
// agent population; a production build likely wants this backed by
// something that indexes edges natively (Neo4j, or Postgres with a
// recursive CTE) once the graph gets large.
type InMemoryGraph struct {
	mu    sync.Mutex
	nodes map[string]Node
	edges []Edge
}

func NewInMemoryGraph() *InMemoryGraph {
	return &InMemoryGraph{nodes: make(map[string]Node)}
}

func (g *InMemoryGraph) AddNode(_ context.Context, n Node) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.nodes[n.ID] = n
	return nil
}

func (g *InMemoryGraph) AddEdge(_ context.Context, e Edge) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.edges = append(g.edges, e)
	return nil
}

func (g *InMemoryGraph) Neighbors(_ context.Context, id string, kind EdgeKind) ([]Node, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	var out []Node
	for _, e := range g.edges {
		if e.From == id && e.Kind == kind {
			if n, ok := g.nodes[e.To]; ok {
				out = append(out, n)
			}
		}
	}
	return out, nil
}

func (g *InMemoryGraph) Reachable(_ context.Context, id string, kinds []EdgeKind) ([]Node, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	allowed := make(map[EdgeKind]bool, len(kinds))
	for _, k := range kinds {
		allowed[k] = true
	}

	visited := map[string]bool{id: true}
	queue := []string{id}
	var out []Node

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, e := range g.edges {
			if e.From != cur || !allowed[e.Kind] {
				continue
			}
			if visited[e.To] {
				continue
			}
			visited[e.To] = true
			if n, ok := g.nodes[e.To]; ok {
				out = append(out, n)
			}
			queue = append(queue, e.To)
		}
	}
	return out, nil
}

// Summary is the aggregate shape of a blast-radius query: not the full
// node list Reachable returns, but how many of each kind it contains,
// the number an incident review actually wants first. Deliberately a
// pure function of a node list rather than a method on Graph, it has no
// reason to touch the store or take a context, callers just hand it
// whatever Reachable already gave them.
type Summary struct {
	Total  int
	ByKind map[NodeKind]int
}

func Summarize(nodes []Node) Summary {
	s := Summary{ByKind: make(map[NodeKind]int)}
	for _, n := range nodes {
		s.Total++
		s.ByKind[n.Kind]++
	}
	return s
}

var _ Graph = (*InMemoryGraph)(nil)
