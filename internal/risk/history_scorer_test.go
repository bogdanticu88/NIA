package risk

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/bogdanticu88/nia/internal/registry/tools"
	"github.com/bogdanticu88/nia/internal/sensitivity"
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
	s := NewHistoryScorer(nil, nil, DefaultWeights())
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
	s := NewHistoryScorer(nil, nil, DefaultWeights())
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
	s := NewHistoryScorer(nil, nil, DefaultWeights())
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
	s := NewHistoryScorer(fakeToolReader{tool: tools.Tool{Name: "wire-transfer", RiskClass: tools.RiskDestructive}}, nil, weights)

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
	s := NewHistoryScorer(fakeToolReader{tool: tools.Tool{Name: "invoices.read", RiskClass: tools.RiskReadOnly}}, nil, weights)

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
	s := NewHistoryScorer(fakeToolReader{err: tools.ErrNotFound}, nil, DefaultWeights())

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
	s := NewHistoryScorer(nil, nil, DefaultWeights())
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

func TestHistoryScorer_SensitiveResourceSignalWhenClassifierConfigured(t *testing.T) {
	weights := DefaultWeights()
	classifier := sensitivity.NewRuleClassifier([]sensitivity.Rule{
		{Pattern: "customer.ssn", Level: sensitivity.Critical},
	})
	s := NewHistoryScorer(nil, classifier, weights)

	score, err := s.Score(context.Background(), CallContext{
		AgentRef:  "agent:billing",
		Tool:      "database.query",
		Resources: []string{"customer.name", "customer.ssn"},
	})
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	want := weights.NovelTool + weights.SensitiveResource + weights.CriticalResource
	if score.Value != want {
		t.Fatalf("Value = %v, want %v (novel_tool + sensitive + critical)", score.Value, want)
	}
	found := false
	for _, sig := range score.Signals {
		if sig.Name == "sensitive_resource:critical" {
			found = true
		}
	}
	if !found {
		t.Fatalf("got %v, want a sensitive_resource:critical signal", score.Signals)
	}
}

func TestHistoryScorer_ResourceBelowSensitiveThresholdContributesNothing(t *testing.T) {
	weights := DefaultWeights()
	classifier := sensitivity.NewRuleClassifier([]sensitivity.Rule{
		{Pattern: "customer.name", Level: sensitivity.Internal},
	})
	s := NewHistoryScorer(nil, classifier, weights)

	score, err := s.Score(context.Background(), CallContext{
		AgentRef:  "agent:billing",
		Tool:      "database.query",
		Resources: []string{"customer.name"},
	})
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	// Only novel_tool should show up, Internal is below the Sensitive
	// threshold this scorer requires before it adds any weight.
	if len(score.Signals) != 1 || score.Signals[0].Name != "novel_tool" {
		t.Fatalf("got %v, want only novel_tool for a resource classified below Sensitive", score.Signals)
	}
}

func TestHistoryScorer_NoClassifierConfiguredSkipsResourceSignalEntirely(t *testing.T) {
	s := NewHistoryScorer(nil, nil, DefaultWeights())

	score, err := s.Score(context.Background(), CallContext{
		AgentRef:  "agent:billing",
		Tool:      "database.query",
		Resources: []string{"customer.ssn"},
	})
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	if len(score.Signals) != 1 || score.Signals[0].Name != "novel_tool" {
		t.Fatalf("got %v, want only novel_tool when no sensitivity.Classifier is configured", score.Signals)
	}
}

var _ Scorer = (*HistoryScorer)(nil)

func TestHistoryScorer_NovelTransitionIsScored(t *testing.T) {
	s := NewHistoryScorer(nil, nil, DefaultWeights())
	ctx := context.Background()
	base := time.Now()

	// a, then b: b is a novel tool and a -> b a novel transition, so the
	// first score carries both.
	if _, err := s.Score(ctx, CallContext{AgentRef: "agent:billing", Tool: "a", At: base}); err != nil {
		t.Fatalf("Score a: %v", err)
	}
	second, err := s.Score(ctx, CallContext{AgentRef: "agent:billing", Tool: "b", At: base.Add(time.Second)})
	if err != nil {
		t.Fatalf("Score b: %v", err)
	}
	want := DefaultWeights().NovelTool + DefaultWeights().NovelTransition
	if second.Value != want {
		t.Fatalf("Value = %v, want %v (novel_tool + novel_transition)", second.Value, want)
	}

	// Back to a: the tool is familiar, the ordering b -> a is not, so
	// novel_transition fires alone. This is the case the signal exists
	// for, an agent using tools it is allowed to use in an order it has
	// never used them in.
	third, err := s.Score(ctx, CallContext{AgentRef: "agent:billing", Tool: "a", At: base.Add(2 * time.Second)})
	if err != nil {
		t.Fatalf("Score a again: %v", err)
	}
	if len(third.Signals) != 1 || third.Signals[0].Name != "novel_transition" {
		t.Fatalf("Signals = %v, want exactly one novel_transition", third.Signals)
	}
	if third.Value != DefaultWeights().NovelTransition {
		t.Fatalf("Value = %v, want %v", third.Value, DefaultWeights().NovelTransition)
	}
}

func TestHistoryScorer_CallRateFiresOnlyAboveTheThreshold(t *testing.T) {
	const threshold = 3
	s := NewHistoryScorerWithHistory(nil, nil, DefaultWeights(), NewInMemoryCallHistory(), time.Minute, threshold)
	ctx := context.Background()
	base := time.Now()

	// Calls 1 through 3 are at or under the threshold, none fires.
	for i := 0; i < threshold; i++ {
		score, err := s.Score(ctx, CallContext{AgentRef: "agent:billing", Tool: "a", At: base.Add(time.Duration(i) * time.Second)})
		if err != nil {
			t.Fatalf("Score #%d: %v", i, err)
		}
		if hasSignal(score, "call_rate") {
			t.Fatalf("call_rate fired on call %d of a %d-call threshold: %v", i+1, threshold, score.Signals)
		}
	}
	// The fourth is the first one over.
	score, err := s.Score(ctx, CallContext{AgentRef: "agent:billing", Tool: "a", At: base.Add(4 * time.Second)})
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	if !hasSignal(score, "call_rate") {
		t.Fatalf("call_rate did not fire on the call that crossed the threshold: %v", score.Signals)
	}
}

func TestHistoryScorer_CallRateDoesNotFireAfterTheWindowPasses(t *testing.T) {
	s := NewHistoryScorerWithHistory(nil, nil, DefaultWeights(), NewInMemoryCallHistory(), time.Minute, 2)
	ctx := context.Background()
	base := time.Now()

	for i := 0; i < 5; i++ {
		if _, err := s.Score(ctx, CallContext{AgentRef: "agent:billing", Tool: "a", At: base.Add(time.Duration(i) * time.Second)}); err != nil {
			t.Fatalf("Score #%d: %v", i, err)
		}
	}
	// An hour later the burst has aged out of the window entirely.
	score, err := s.Score(ctx, CallContext{AgentRef: "agent:billing", Tool: "a", At: base.Add(time.Hour)})
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	if hasSignal(score, "call_rate") {
		t.Fatalf("call_rate fired on a call an hour after the burst: %v", score.Signals)
	}
}

func TestHistoryScorer_RateTrackingOffByDefault(t *testing.T) {
	s := NewHistoryScorer(nil, nil, DefaultWeights())
	ctx := context.Background()
	base := time.Now()
	for i := 0; i < 100; i++ {
		score, err := s.Score(ctx, CallContext{AgentRef: "agent:billing", Tool: "a", At: base.Add(time.Duration(i) * time.Millisecond)})
		if err != nil {
			t.Fatalf("Score #%d: %v", i, err)
		}
		if hasSignal(score, "call_rate") {
			t.Fatalf("call_rate fired with no rate configuration, on call %d", i+1)
		}
	}
}

// failingHistory proves a history failure is a real error rather than a
// silent zero score: a call nobody could baseline must not look like a
// call that simply wasn't interesting.
type failingHistory struct{}

func (failingHistory) Observe(context.Context, string, string, time.Time, time.Duration) (Observation, error) {
	return Observation{}, errHistoryDown
}

var errHistoryDown = errors.New("call history unreachable")

func TestHistoryScorer_HistoryFailureIsAnErrorNotAZeroScore(t *testing.T) {
	s := NewHistoryScorerWithHistory(nil, nil, DefaultWeights(), failingHistory{}, time.Minute, 5)
	score, err := s.Score(context.Background(), CallContext{AgentRef: "agent:billing", Tool: "a", At: time.Now()})
	if err == nil {
		t.Fatalf("Score = %+v, nil, want an error when the history cannot be read", score)
	}
}

func hasSignal(s Score, name string) bool {
	for _, sig := range s.Signals {
		if sig.Name == name {
			return true
		}
	}
	return false
}
