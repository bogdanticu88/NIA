package risk

import (
	"context"
	"sync"
	"time"

	"github.com/bogdanticu88/nia/internal/registry/tools"
	"github.com/bogdanticu88/nia/internal/sensitivity"
)

// Weights configures how much each signal HistoryScorer knows about
// contributes to a call's score.
type Weights struct {
	NovelTool            float64
	RiskClassReadOnly    float64
	RiskClassWrite       float64
	RiskClassDestructive float64

	// SensitiveResource is added once when any resource a call's
	// arguments touched classifies at sensitivity.Sensitive or above.
	// CriticalResource is added on top of that, not instead of it, when
	// the highest classification found is sensitivity.Critical, so a
	// critical-resource call always weighs strictly more than a merely
	// sensitive one.
	SensitiveResource float64
	CriticalResource  float64
}

// DefaultWeights is a starting point, not a tuned production value,
// nothing here has run against real traffic yet. A first call to a tool
// weighs as much as a write-class tool; a destructive one weighs three
// times either alone. Touching a sensitive resource weighs twice a
// novel tool call; touching a critical one weighs four times that on
// top, deliberately the heaviest single signal this scorer has, since
// it's the one closest to the directive's own SSN-column example.
func DefaultWeights() Weights {
	return Weights{
		NovelTool:            1,
		RiskClassReadOnly:    0,
		RiskClassWrite:       1,
		RiskClassDestructive: 3,
		SensitiveResource:    2,
		CriticalResource:     4,
	}
}

// HistoryScorer is the first real Scorer, not CENTIPEDE's anomaly
// detection, that's still the intended eventual replacement, see this
// package's own doc comment, but not the flat StaticScorer either.
// Three signals it can compute without any external dependency:
// novel_tool, has this agent ever called this exact tool before,
// tracked in process memory; when a tools.Reader is configured,
// risk_class, weighted by how destructive the tool itself is
// classified in the catalog; and, when a sensitivity.Classifier is
// configured and the call carries any Resources, sensitive_resource,
// weighted by the highest sensitivity level any of them classify at.
// volume_deviation, Signal's doc comment's remaining named example,
// needs rate tracking this scaffold doesn't have yet, left out rather
// than faked.
//
// The in-process history means what CENTIPEDE's own baselining will
// eventually need a real backend for: restart cmd/gateway and every
// tool looks novel again, and a second gateway replica has its own
// separate view of what's novel for a given agent. Called out here for
// the same reason internal/audit called out its own pre-PostgresSink
// per-process state, a known scaffold limitation, not a silent one.
type HistoryScorer struct {
	mu        sync.Mutex
	history   map[string]map[string]struct{} // agentRef -> tool names already seen
	toolCat   tools.Reader                   // optional, nil skips the risk_class signal entirely
	sensitive sensitivity.Classifier         // optional, nil skips the sensitive_resource signal entirely
	weights   Weights
}

// NewHistoryScorer builds a scorer. toolCat and sensitive may each be
// nil independently, in which case the signal each backs is skipped;
// with both nil only novel_tool is computed.
func NewHistoryScorer(toolCat tools.Reader, sensitive sensitivity.Classifier, weights Weights) *HistoryScorer {
	return &HistoryScorer{
		history:   make(map[string]map[string]struct{}),
		toolCat:   toolCat,
		sensitive: sensitive,
		weights:   weights,
	}
}

func (s *HistoryScorer) Score(ctx context.Context, call CallContext) (Score, error) {
	novel := s.observe(call.AgentRef, call.Tool)

	var signals []Signal
	var total float64
	if novel {
		signals = append(signals, Signal{Name: "novel_tool", Weight: s.weights.NovelTool})
		total += s.weights.NovelTool
	}

	if s.toolCat != nil {
		// A lookup failure, including the tool not being registered at
		// all, is not scored and does not fail Score: this runs after
		// the policy check already allowed the call, see CallContext's
		// own doc comment, scoring is best-effort observation, not a
		// second authorization gate, that gate is cmd/gateway's tool
		// catalog check, upstream of this.
		if tool, err := s.toolCat.Get(ctx, call.Tool); err == nil {
			if w := s.riskClassWeight(tool.RiskClass); w != 0 {
				signals = append(signals, Signal{Name: "risk_class:" + string(tool.RiskClass), Weight: w})
				total += w
			}
		}
	}

	if s.sensitive != nil && len(call.Resources) > 0 {
		max := sensitivity.Public
		for _, r := range call.Resources {
			if lvl := s.sensitive.Classify(r); lvl > max {
				max = lvl
			}
		}
		if max >= sensitivity.Sensitive {
			w := s.weights.SensitiveResource
			if max == sensitivity.Critical {
				w += s.weights.CriticalResource
			}
			if w != 0 {
				signals = append(signals, Signal{Name: "sensitive_resource:" + max.String(), Weight: w})
				total += w
			}
		}
	}

	return Score{
		AgentRef: call.AgentRef,
		Value:    total,
		Signals:  signals,
		ScoredAt: time.Now(),
	}, nil
}

// observe records this (agent, tool) pair and reports whether it was
// novel, atomically, so two concurrent first-calls for the same
// (agent, tool) can't both report novel and double-count the signal.
func (s *HistoryScorer) observe(agentRef, tool string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	seen, ok := s.history[agentRef]
	if !ok {
		seen = make(map[string]struct{})
		s.history[agentRef] = seen
	}
	if _, called := seen[tool]; called {
		return false
	}
	seen[tool] = struct{}{}
	return true
}

func (s *HistoryScorer) riskClassWeight(class tools.RiskClass) float64 {
	switch class {
	case tools.RiskReadOnly:
		return s.weights.RiskClassReadOnly
	case tools.RiskWrite:
		return s.weights.RiskClassWrite
	case tools.RiskDestructive:
		return s.weights.RiskClassDestructive
	default:
		return 0
	}
}

var _ Scorer = (*HistoryScorer)(nil)
