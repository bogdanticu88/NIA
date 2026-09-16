package graph

import (
	"context"
	"testing"
)

// TestReachableFollowsDelegationChains is the blast-radius query from
// docs/DATA_MODEL.md: given a compromised agent, what else can it reach
// transitively through delegation and grants.
func TestReachableFollowsDelegationChains(t *testing.T) {
	ctx := context.Background()
	g := NewInMemoryGraph()

	_ = g.AddNode(ctx, Node{ID: "agent:a", Kind: NodeAgent})
	_ = g.AddNode(ctx, Node{ID: "agent:b", Kind: NodeAgent})
	_ = g.AddNode(ctx, Node{ID: "agent:c", Kind: NodeAgent})
	_ = g.AddNode(ctx, Node{ID: "tool:invoice-api", Kind: NodeTool})

	_ = g.AddEdge(ctx, Edge{From: "agent:a", To: "agent:b", Kind: EdgeDelegatesTo})
	_ = g.AddEdge(ctx, Edge{From: "agent:b", To: "agent:c", Kind: EdgeDelegatesTo})
	_ = g.AddEdge(ctx, Edge{From: "agent:c", To: "tool:invoice-api", Kind: EdgeGrants})

	reachable, err := g.Reachable(ctx, "agent:a", []EdgeKind{EdgeDelegatesTo, EdgeGrants})
	if err != nil {
		t.Fatalf("Reachable: %v", err)
	}

	ids := map[string]bool{}
	for _, n := range reachable {
		ids[n.ID] = true
	}

	for _, want := range []string{"agent:b", "agent:c", "tool:invoice-api"} {
		if !ids[want] {
			t.Fatalf("expected %s to be reachable from agent:a, got %v", want, ids)
		}
	}
}

func TestSummarize_CountsByKind(t *testing.T) {
	nodes := []Node{
		{ID: "agent:b", Kind: NodeAgent},
		{ID: "agent:c", Kind: NodeAgent},
		{ID: "tool:invoice-api", Kind: NodeTool},
		{ID: "customer.ssn", Kind: NodeData},
	}
	s := Summarize(nodes)
	if s.Total != 4 {
		t.Fatalf("Total = %d, want 4", s.Total)
	}
	if s.ByKind[NodeAgent] != 2 || s.ByKind[NodeTool] != 1 || s.ByKind[NodeData] != 1 {
		t.Fatalf("ByKind = %v, want agent:2 tool:1 data:1", s.ByKind)
	}
}

func TestSummarize_EmptyList(t *testing.T) {
	s := Summarize(nil)
	if s.Total != 0 {
		t.Fatalf("Total = %d, want 0 for an empty reachable list", s.Total)
	}
	if len(s.ByKind) != 0 {
		t.Fatalf("ByKind = %v, want empty", s.ByKind)
	}
}
