package risk

import (
	"context"
	"fmt"
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

	// NovelTransition fires when the agent goes from one tool straight
	// to another in an order it has never used before, see
	// Observation.NovelTransition. Weighed below novel_tool
	// deliberately: doing a familiar thing in an unfamiliar order is a
	// weaker signal than doing something never done at all, and a
	// legitimate agent reorders its own work often enough that this
	// would be noisy at a heavier weight.
	NovelTransition float64

	// CallRate fires once when the agent's call count inside the
	// configured window crosses the configured threshold, see
	// NewHistoryScorerWithHistory. Deliberately a single flat weight
	// per call rather than something that scales with how far over the
	// threshold the agent is: a scaling term compounds with the running
	// cumulative total internal/monitoring already keeps, and a burst
	// would cross a kill threshold on arithmetic nobody can explain
	// after the fact. Explainable over clever, the same choice
	// internal/sensitivity's flat rule list makes.
	CallRate float64
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
		NovelTransition:      0.5,
		CallRate:             2,
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
// Two more as of the gap-closing pass, both from CallHistory rather
// than from anything this type keeps itself: novel_transition, the
// agent going from one tool to another in an order it has never used
// before, and call_rate, the agent's call count inside a configured
// window crossing a configured threshold. Those close what
// docs/THREAT_MODEL.md's threat 10 called out as an entirely uncovered
// category, every signal before them judged one call in isolation and
// nothing looked at volume or ordering at all.
//
// Where the behavioural memory lives is now a deployment choice, see
// CallHistory. The default is still per process and lost on restart,
// which has a sharper consequence than it looks: with several gateway
// replicas the same tool counts as novel once per replica, and every
// restart makes the whole catalog novel again, so a risk total that
// internal/monitoring.PostgresRiskStore shares correctly is still being
// fed by inputs that are neither shared nor stable. PostgresCallHistory
// is what makes the inputs match the total.
type HistoryScorer struct {
	history       CallHistory
	toolCat       tools.Reader           // optional, nil skips the risk_class signal entirely
	sensitive     sensitivity.Classifier // optional, nil skips the sensitive_resource signal entirely
	weights       Weights
	rateWindow    time.Duration // zero disables rate tracking entirely
	rateThreshold int           // calls inside rateWindow above which call_rate fires
}

// NewHistoryScorer builds a scorer with a process-local history and no
// rate tracking, the behaviour this type had before CallHistory
// existed. toolCat and sensitive may each be nil independently, in
// which case the signal each backs is skipped.
func NewHistoryScorer(toolCat tools.Reader, sensitive sensitivity.Classifier, weights Weights) *HistoryScorer {
	return NewHistoryScorerWithHistory(toolCat, sensitive, weights, NewInMemoryCallHistory(), 0, 0)
}

// NewHistoryScorerWithHistory is NewHistoryScorer with the behavioural
// memory and the rate configuration supplied, the same
// NewMonitor/NewMonitorWithRiskStore split internal/monitoring uses for
// the same reason: the shared, Postgres-backed variant is a deployment
// choice, not a different scorer.
//
// rateWindow zero, or rateThreshold zero or less, disables the
// call_rate signal and stops the history from tracking timestamps at
// all. That is the default and it is deliberate: a rate threshold
// nobody chose for their own traffic is worse than none, it would
// either never fire or fire on every busy agent, and internal/monitoring
// accumulates whatever this returns straight into a total that can kill
// an agent.
func NewHistoryScorerWithHistory(toolCat tools.Reader, sensitive sensitivity.Classifier, weights Weights, history CallHistory, rateWindow time.Duration, rateThreshold int) *HistoryScorer {
	if history == nil {
		history = NewInMemoryCallHistory()
	}
	return &HistoryScorer{
		history:       history,
		toolCat:       toolCat,
		sensitive:     sensitive,
		weights:       weights,
		rateWindow:    rateWindow,
		rateThreshold: rateThreshold,
	}
}

func (s *HistoryScorer) Score(ctx context.Context, call CallContext) (Score, error) {
	at := call.At
	if at.IsZero() {
		at = time.Now()
	}
	// A history failure is a real error, unlike the tool-catalog lookup
	// below. The catalog only enriches a score; the history is what
	// decides whether this call is novel at all, and silently scoring 0
	// for a call nobody could baseline would look identical to a call
	// that genuinely wasn't interesting. cmd/gateway treats a scoring
	// error as fail-open for the request itself (the call was already
	// authorized) but audits it, see its observe method.
	obs, err := s.history.Observe(ctx, call.AgentRef, call.Tool, at, s.rateWindow)
	if err != nil {
		return Score{}, fmt.Errorf("risk: observing call history: %w", err)
	}

	var signals []Signal
	var total float64
	if obs.NovelTool {
		signals = append(signals, Signal{Name: "novel_tool", Weight: s.weights.NovelTool})
		total += s.weights.NovelTool
	}
	if obs.NovelTransition && s.weights.NovelTransition != 0 {
		signals = append(signals, Signal{Name: "novel_transition", Weight: s.weights.NovelTransition})
		total += s.weights.NovelTransition
	}
	if s.rateWindow > 0 && s.rateThreshold > 0 && obs.RecentCalls+1 > s.rateThreshold && s.weights.CallRate != 0 {
		signals = append(signals, Signal{Name: "call_rate", Weight: s.weights.CallRate})
		total += s.weights.CallRate
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
