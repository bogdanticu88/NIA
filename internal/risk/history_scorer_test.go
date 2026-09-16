package risk

import (
	"context"
	"sync"
	"testing"

	"github.com/bogdanticu88/nia/internal/registry/tools"
)

// fakeToolReader lets a test control what the catalog says about a
// tool without a real cmd/api to talk to.
type fakeToolReader struct {
	tool tools.Tool
	err  error
}

func (f fakeToolReader) Get(_ context.Context, name string) (tools.Tool, error) {
	if f.err != nil {
		return tools.Tool{}, f.err
	}
	return f.tool, nil
}

func TestHistoryScorer_FirstCallIsNovel(t *testing.T) {
	s := NewHistoryScorer(nil, DefaultWeights())
	score, err := s.Score(context.Background(), CallContext{AgentRef: "agent:billing", Tool: "invoices.read"})
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	if score.Value != DefaultWeights().NovelTool {
		t.Fatalf("Value = %v, want %v for a first call", score.Value, DefaultWeights().NovelTool)
	}
	if len(score.Signals) != 1 || score.Signals[0].Name != "novel_tool" {
		t.Fatalf("Signals = %v, want exactly one novel_tool signal", score.Signals)
	}
}

func TestHistoryScorer_RepeatCallIsNotNovel(t *testing.T) {
	s := NewHistoryScorer(nil, DefaultWeights())
	ctx := context.Background()
	call := CallContext{AgentRef: "agent:billing", Tool: "invoices.read"}

	if _, err := s.Score(ctx, call); err != nil {
		t.Fatalf("first Score: %v", err)
	}
	second, err := s.Score(ctx, call)
	if err != nil {
		t.Fatalf("second Score: %v", err)
	}
	if second.Value != 0 || len(second.Signals) != 0 {
		t.Fatalf("got %+v, want a zero score for a tool this agent already called", second)
	}
}

func TestHistoryScorer_NoveltyIsPerAgent(t *testing.T) {
	s := NewHistoryScorer(nil, DefaultWeights())
	ctx := context.Background()

	if _, err := s.Score(ctx, CallContext{AgentRef: "agent:billing", Tool: "invoices.read"}); err != nil {
		t.Fatalf("Score: %v", err)
	}
	other, err := s.Score(ctx, CallContext{AgentRef: "agent:reporting", Tool: "invoices.read"})
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	if other.Value != DefaultWeights().NovelTool {
		t.Fatalf("got %v, want a different agent's first call to still be novel", other.Value)
	}
}

func TestHistoryScorer_RiskClassSignalWhenCatalogConfigured(t *testing.T) {
	weights := DefaultWeights()
	s := NewHistoryScorer(fakeToolReader{tool: tools.Tool{Name: "wire-transfer", RiskClass: tools.RiskDestructive}}, weights)

	score, err := s.Score(context.Background(), CallContext{AgentRef: "agent:billing", Tool: "wire-transfer"})
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	want := weights.NovelTool + weights.RiskClassDestructive
	if score.Value != want {
		t.Fatalf("Value = %v, want %v (novel_tool + destructive)", score.Value, want)
	}
	if len(score.Signals) != 2 {
		t.Fatalf("got %d signals, want 2: %v", len(score.Signals), score.Signals)
	}
}

func TestHistoryScorer_ReadOnlyDefaultWeightContributesNothing(t *testing.T) {
	weights := DefaultWeights()
	s := NewHistoryScorer(fakeToolReader{tool: tools.Tool{Name: "invoices.read", RiskClass: tools.RiskReadOnly}}, weights)

	score, err := s.Score(context.Background(), CallContext{AgentRef: "agent:billing", Tool: "invoices.read"})
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	// Only novel_tool should show up, the default read_only weight is 0.
	if len(score.Signals) != 1 || score.Signals[0].Name != "novel_tool" {
		t.Fatalf("got %v, want only the novel_tool signal for a read_only tool at default weights", score.Signals)
	}
}

func TestHistoryScorer_CatalogLookupErrorIsNotScoredAndDoesNotFail(t *testing.T) {
	s := NewHistoryScorer(fakeToolReader{err: tools.ErrNotFound}, DefaultWeights())

	score, err := s.Score(context.Background(), CallContext{AgentRef: "agent:billing", Tool: "unregistered-tool"})
	if err != nil {
		t.Fatalf("Score returned an error for a catalog lookup failure, want nil: %v", err)
	}
	// novel_tool still fires, risk_class does not.
	if len(score.Signals) != 1 || score.Signals[0].Name != "novel_tool" {
		t.Fatalf("got %v, want only novel_tool when the catalog lookup fails", score.Signals)
	}
}

func TestHistoryScorer_ConcurrentFirstCallsForSamePairOnlyCountOneNovelty(t *testing.T) {
	s := NewHistoryScorer(nil, DefaultWeights())
	ctx := context.Background()
	call := CallContext{AgentRef: "agent:billing", Tool: "invoices.read"}

	const n = 50
	scores := make([]Score, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			score, err := s.Score(ctx, call)
			if err != nil {
				t.Errorf("Score: %v", err)
				return
			}
			scores[i] = score
		}(i)
	}
	wg.Wait()

	novelCount := 0
	for _, sc := range scores {
		if sc.Value == DefaultWeights().NovelTool {
			novelCount++
		}
	}
	if novelCount != 1 {
		t.Fatalf("got %d concurrent calls scored as novel for the same (agent, tool), want exactly 1", novelCount)
	}
}

var _ Scorer = (*HistoryScorer)(nil)
