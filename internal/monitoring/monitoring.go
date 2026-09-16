// Package monitoring watches what agents actually do at runtime and
// decides when a risk score crosses into a detect/block/revoke
// response. It sits downstream of the gateway (which has already made
// the live allow/deny call) and downstream of internal/risk (which has
// already scored the call); this package's job is purely the response
// side: decide, and act.
package monitoring

import (
	"context"
	"fmt"
	"time"

	"github.com/bogdanticu88/nia/internal/audit"
	"github.com/bogdanticu88/nia/internal/credentials"
	"github.com/bogdanticu88/nia/internal/policy"
	"github.com/bogdanticu88/nia/internal/risk"
)

// Action is what the monitor decided to do about a scored call.
type Action string

const (
	ActionNone   Action = "none"
	ActionFlag   Action = "flag"   // logged, no enforcement
	ActionRevoke Action = "revoke" // this agent's active credentials revoked, identity and grants otherwise untouched
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
// into internal/policy or internal/credentials to act and internal/audit
// to record why.
type Monitor struct {
	thresholds Threshold
	policy     policy.Client
	creds      credentials.Store // optional, nil means ActionRevoke is a documented no-op, see revokeCredentials
	audit      audit.Sink
}

// NewMonitor builds a Monitor. creds may be nil: a deployment that
// hasn't wired a credentials.Store into whatever process runs this
// (cmd/gateway doesn't have one today, see cmd/gateway's own doc
// comment) still gets flag and kill behavior, ActionRevoke degrades to
// a no-op that says so in its own audit detail rather than silently
// pretending to have revoked something.
func NewMonitor(t Threshold, p policy.Client, creds credentials.Store, a audit.Sink) *Monitor {
	return &Monitor{thresholds: t, policy: p, creds: creds, audit: a}
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

	detail := "risk score crossed threshold"
	switch action {
	case ActionKill:
		if _, err := m.policy.Kill(ctx, score.AgentRef, incident, "monitoring"); err != nil {
			return action, err
		}
	case ActionRevoke:
		revoked, configured, err := m.revokeCredentials(ctx, score.AgentRef, incident)
		if err != nil {
			return action, err
		}
		switch {
		case !configured:
			detail = "risk score crossed the revoke threshold, but this process has no credentials.Store configured, nothing was revoked"
		case revoked == 0:
			detail = "risk score crossed the revoke threshold, agent had no active credentials to revoke"
		default:
			detail = fmt.Sprintf("risk score crossed threshold, revoked %d active credential(s)", revoked)
		}
	}

	return action, m.audit.Append(ctx, audit.Event{
		Action:   "monitoring." + string(action),
		AgentRef: score.AgentRef,
		Operator: "monitoring",
		Incident: incident,
		Detail:   detail,
		At:       time.Now(),
	})
}

// revokeCredentials retires every currently active credential belonging
// to agentRef. This is coarser than "one credential", the scaffold has
// no way to attribute a single call to the specific credential that
// authenticated it, see cmd/gateway's headerResolver, which resolves an
// agent ref, not a credential id. Revoking every active credential is
// the honest version of "cut this agent's access without the full kill
// switch" available today; configured reports whether a store was even
// wired in, so a caller building the audit detail can tell "revoked
// zero because none were active" apart from "couldn't revoke anything,
// nothing to revoke against."
func (m *Monitor) revokeCredentials(ctx context.Context, agentRef, incident string) (revoked int, configured bool, err error) {
	if m.creds == nil {
		return 0, false, nil
	}
	creds, err := m.creds.ListForAgent(ctx, agentRef)
	if err != nil {
		return 0, true, err
	}
	for _, c := range creds {
		if c.Status != credentials.StatusActive {
			continue
		}
		if err := m.creds.Revoke(ctx, c.ID, "monitoring", "risk score crossed the revoke threshold ("+incident+")"); err != nil {
			return revoked, true, err
		}
		revoked++
	}
	return revoked, true, nil
}
