package incident

import (
	"context"
	"testing"

	"github.com/bogdanticu88/nia/internal/risk"
)

func TestCreate_AssignsAnID(t *testing.T) {
	s := NewInMemoryStore()
	in, err := s.Create(context.Background(), Incident{AgentRef: "agent:billing", Action: "flag"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if in.ID == "" {
		t.Fatal("Create did not assign an ID")
	}
}

func TestGet_ReturnsWhatWasCreated(t *testing.T) {
	s := NewInMemoryStore()
	created, err := s.Create(context.Background(), Incident{
		AgentRef:    "agent:billing",
		IncidentRef: "auto-risk-1",
		Action:      "kill",
		RiskValue:   20,
		Cumulative:  24,
		Signals:     []risk.Signal{{Name: "novel_tool", Weight: 3}},
		Reason:      "cumulative risk 24 crossed threshold",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := s.Get(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.AgentRef != "agent:billing" || got.Action != "kill" || got.Cumulative != 24 {
		t.Fatalf("got %+v, want the record just created", got)
	}
	if len(got.Signals) != 1 || got.Signals[0].Name != "novel_tool" {
		t.Fatalf("got signals %v, want the novel_tool signal preserved", got.Signals)
	}
}

func TestGet_UnknownID(t *testing.T) {
	s := NewInMemoryStore()
	_, err := s.Get(context.Background(), "inc-does-not-exist")
	if err != ErrNotFound {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestList_OldestFirst(t *testing.T) {
	s := NewInMemoryStore()
	ctx := context.Background()
	first, _ := s.Create(ctx, Incident{AgentRef: "agent:billing", Action: "flag"})
	second, _ := s.Create(ctx, Incident{AgentRef: "agent:billing", Action: "kill"})

	out, err := s.List(ctx, "", 0)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(out) != 2 || out[0].ID != first.ID || out[1].ID != second.ID {
		t.Fatalf("got %v, want [first, second] in creation order", out)
	}
}

func TestList_FiltersByAgent(t *testing.T) {
	s := NewInMemoryStore()
	ctx := context.Background()
	s.Create(ctx, Incident{AgentRef: "agent:billing", Action: "flag"})
	s.Create(ctx, Incident{AgentRef: "agent:reporting", Action: "flag"})

	out, err := s.List(ctx, "agent:reporting", 0)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(out) != 1 || out[0].AgentRef != "agent:reporting" {
		t.Fatalf("got %v, want only agent:reporting's incident", out)
	}
}

func TestList_RespectsLimit_KeepsMostRecent(t *testing.T) {
	s := NewInMemoryStore()
	ctx := context.Background()
	s.Create(ctx, Incident{AgentRef: "agent:billing", Action: "flag"})
	s.Create(ctx, Incident{AgentRef: "agent:billing", Action: "revoke"})
	third, _ := s.Create(ctx, Incident{AgentRef: "agent:billing", Action: "kill"})

	out, err := s.List(ctx, "", 1)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(out) != 1 || out[0].ID != third.ID {
		t.Fatalf("got %v, want only the most recent incident when limit is 1", out)
	}
}

func TestList_EmptyStore(t *testing.T) {
	s := NewInMemoryStore()
	out, err := s.List(context.Background(), "", 0)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("got %v, want no incidents from an empty store", out)
	}
}
