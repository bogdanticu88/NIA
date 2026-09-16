// Package risk scores agents and individual calls. This has no Tessera
// counterpart, it's net-new. The scaffold here keeps the shape thin: a
// real scorer wants historical baselining per
// agent (what does this agent normally call, at what volume, touching
// what data) before its output means anything, and that's exactly the
// kind of anomaly-detection problem CENTIPEDE was already built for.
// The intent is for CENTIPEDE's detection logic to become a Scorer
// implementation here rather than NIA growing a second anomaly engine.
package risk

import (
	"context"
	"time"
)

// Signal is one input into a risk score: something observed about a
// call that's worth weighing. Kept as a flat list rather than a fixed
// struct so new signal types don't require an interface change.
type Signal struct {
	Name   string // e.g. "novel_tool", "sensitive_data_touched", "volume_deviation"
	Weight float64
}

// Score is the outcome of scoring one call or one agent's recent
// behavior. Value is unbounded, callers decide their own thresholds
// for what counts as "block this."
type Score struct {
	AgentRef string
	Value    float64
	Signals  []Signal
	ScoredAt time.Time
}

// CallContext is what the monitoring pipeline hands the scorer for one
// tool/data call already permitted by the policy check. Scoring happens
// after authorization, not instead of it: an allowed call can still be
// risky enough to flag or to feed back into internal/monitoring's
// detect/block loop.
type CallContext struct {
	AgentRef string
	Tool     string
	At       time.Time

	// Resources are the resource object names this call's arguments
	// touched, named the same way policy.GrantForData and
	// sensitivity.Rule name them, "customer.ssn" and so on. Left empty
	// when the caller didn't derive any, either because the tool call
	// had no arguments worth inspecting or because argument inspection
	// isn't configured, see cmd/gateway's ArgumentResourcePolicy.
	Resources []string
}

// Scorer produces a Score for a call. Implementations are expected to
// keep their own per-agent history; this interface doesn't assume a
// particular storage strategy.
type Scorer interface {
	Score(ctx context.Context, call CallContext) (Score, error)
}

// StaticScorer is the reference implementation: every call scores the
// same flat baseline. It exists so the rest of the pipeline (monitoring,
// detect/block) can be wired and tested before a real scorer, backed by
// CENTIPEDE's anomaly detection, is plugged in.
type StaticScorer struct {
	Baseline float64
}

func NewStaticScorer() *StaticScorer {
	return &StaticScorer{Baseline: 0}
}

func (s *StaticScorer) Score(_ context.Context, call CallContext) (Score, error) {
	return Score{
		AgentRef: call.AgentRef,
		Value:    s.Baseline,
		ScoredAt: time.Now(),
	}, nil
}

var _ Scorer = (*StaticScorer)(nil)
