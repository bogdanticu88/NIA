// Package monitoring watches what agents actually do at runtime and
// decides when a risk score crosses into a detect/block/revoke
// response. It sits downstream of the gateway (which has already made
// the live allow/deny call) and downstream of internal/risk (which has
// already scored the call); this package's job is purely the response
// side: decide, and act.
package monitoring

import (
	"context"
	"time"

	"github.com/bogdanticu88/nia/internal/audit"
	"github.com/bogdanticu88/nia/internal/policy"
	"github.com/bogdanticu88/nia/internal/risk"
)

// Action is what the monitor decided to do about a scored call.
type Action string

const (
	ActionNone   Action = "none"
	ActionFlag   Action = "flag"   // logged, no enforcement
	ActionRevoke Action = "revoke" // one credential revoked, agent otherwise untouched
	ActionKill   Action = "kill"   // full kill switch via internal/policy
)

// Threshold maps a risk score to a response. Kept simple and linear on
// purpose for the scaffold; a real deployment likely wants this
// per-agent or per-tool-risk-class rather than global.
type Threshold struct {
	FlagAt   float64
	RevokeAt float64
	KillAt   float64
}

// Monitor consumes risk scores and, when a threshold is crossed, calls
// into internal/policy to act and internal/audit to record why.
type Monitor struct {
	thresholds Threshold
	policy     policy.Client
	audit      audit.Sink
}

func NewMonitor(t Threshold, p policy.Client, a audit.Sink) *Monitor {
	return &Monitor{thresholds: t, policy: p, audit: a}
}

// Observe takes a risk score and decides + executes a response. Returns
// the action taken so the caller (typically the gateway's request loop)
// can log or surface it.
func (m *Monitor) Observe(ctx context.Context, score risk.Score, incident string) (Action, error) {
	action := ActionNone
	switch {
	case score.Value >= m.thresholds.KillAt:
		action = ActionKill
	case score.Value >= m.thresholds.RevokeAt:
		action = ActionRevoke
	case score.Value >= m.thresholds.FlagAt:
		action = ActionFlag
	default:
		return ActionNone, nil
	}

	if action == ActionKill {
		if _, err := m.policy.Kill(ctx, score.AgentRef, incident, "monitoring"); err != nil {
			return action, err
		}
	}

	return action, m.audit.Append(ctx, audit.Event{
		Action:   "monitoring." + string(action),
		AgentRef: score.AgentRef,
		Operator: "monitoring",
		Incident: incident,
		Detail:   "risk score crossed threshold",
		At:       time.Now(),
	})
}
