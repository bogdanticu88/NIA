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
	"sync"
	"time"

	"github.com/bogdanticu88/nia/internal/audit"
	"github.com/bogdanticu88/nia/internal/credentials"
	"github.com/bogdanticu88/nia/internal/incident"
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
//
// Thresholds are compared against a running total per agent, not a
// single call's score in isolation. One first-time destructive call
// might not be enough to justify a kill on its own, three in a row
// probably is, and neither the directive's own "risk climbs across a
// sequence" framing nor a real compromise looks like a single call, it
// looks like an escalating pattern. The total accumulates from zero and
// only resets when this Monitor actually kills the agent, since a kill
// is the one action that changes the agent's state enough to justify
// starting its risk history over; a flag or a revoke doesn't reset it,
// an agent that keeps behaving badly after a revoke should still be
// closer to a kill, not further from one. This is deliberately simple,
// no time decay, no windowing, a running sum that resets on kill,
// documented here rather than left to guesswork; it needs a real
// backend (see HistoryScorer's own doc comment on its in-process
// history) before it means anything across a restart or a second
// gateway replica, same known scaffold limitation as everything else
// that keeps state in a map today.
type Monitor struct {
	thresholds Threshold
	policy     policy.Client
	creds      credentials.Store // optional, nil means ActionRevoke is a documented no-op, see revokeCredentials
	incidents  incident.Store    // optional, nil means no structured incident record is created, only the audit event
	audit      audit.Sink

	mu         sync.Mutex
	cumulative map[string]float64 // agentRef -> running risk total since the last kill
}

// NewMonitor builds a Monitor. creds may be nil: a deployment that
// hasn't wired a credentials.Store into whatever process runs this
// (cmd/gateway doesn't have one today, see cmd/gateway's own doc
// comment) still gets flag and kill behavior, ActionRevoke degrades to
// a no-op that says so in its own audit detail rather than silently
// pretending to have revoked something. incidents may also be nil: a
// deployment that hasn't wired an incident.Store in still gets the
// audit event Observe always writes, it just doesn't get a structured
// Incident record alongside it, see this file's own package doc comment
// on why the two are different things.
func NewMonitor(t Threshold, p policy.Client, creds credentials.Store, incidents incident.Store, a audit.Sink) *Monitor {
	return &Monitor{thresholds: t, policy: p, creds: creds, incidents: incidents, audit: a, cumulative: make(map[string]float64)}
}

// CumulativeRisk returns the current running total for an agent, 0 if
// Observe has never been called for it or if it was last reset by a
// kill. Exported so callers other than the gateway's own request loop,
// an incident report or a CLI command inspecting an agent's current
// risk, can read the same number Observe itself is comparing against
// the thresholds, rather than each keeping their own view of it.
func (m *Monitor) CumulativeRisk(agentRef string) float64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cumulative[agentRef]
}

// Thresholds returns the flag/revoke/kill thresholds this Monitor was
// built with, so a caller reporting CumulativeRisk (a "niactl risk"
// command, say) can show what that number is being compared against
// without the caller having to separately know or re-derive it.
func (m *Monitor) Thresholds() Threshold {
	return m.thresholds
}

// TrackedAgents returns how many agents currently have a nonzero risk
// history since their last kill, a cheap gauge of "how many agents this
// process has scored at all recently" for /metrics, not a list of who
// they are, see CumulativeRisk for that.
func (m *Monitor) TrackedAgents() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.cumulative)
}

// accumulate adds value to agentRef's running total and returns the new
// total, atomically so concurrent calls for the same agent can't lose
// an update racing each other.
func (m *Monitor) accumulate(agentRef string, value float64) float64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cumulative[agentRef] += value
	return m.cumulative[agentRef]
}

func (m *Monitor) resetCumulative(agentRef string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.cumulative, agentRef)
}

// Observe takes a risk score and decides + executes a response. Returns
// the action taken so the caller (typically the gateway's request loop)
// can log or surface it. incidentRef is the caller-supplied correlator,
// an operator's "INC-001" on a manual kill or the gateway's own
// "auto-risk-<nanos>", it's carried into both the audit event and, when
// this Monitor has an incident.Store configured, the structured
// Incident record Observe creates for any action beyond ActionNone.
func (m *Monitor) Observe(ctx context.Context, score risk.Score, incidentRef string) (Action, error) {
	total := m.accumulate(score.AgentRef, score.Value)

	action := ActionNone
	switch {
	case total >= m.thresholds.KillAt:
		action = ActionKill
	case total >= m.thresholds.RevokeAt:
		action = ActionRevoke
	case total >= m.thresholds.FlagAt:
		action = ActionFlag
	default:
		return ActionNone, nil
	}

	detail := fmt.Sprintf("cumulative risk %.0f crossed threshold", total)
	switch action {
	case ActionKill:
		if _, err := m.policy.Kill(ctx, score.AgentRef, incidentRef, "monitoring"); err != nil {
			return action, err
		}
		// A kill is the one action that actually changes the agent's
		// state, restore plus fresh grants means a fresh start, its
		// risk history shouldn't carry a pre-kill total forward
		// forever, see this type's own doc comment.
		m.resetCumulative(score.AgentRef)
	case ActionRevoke:
		revoked, configured, err := m.revokeCredentials(ctx, score.AgentRef, incidentRef)
		if err != nil {
			return action, err
		}
		switch {
		case !configured:
			detail = fmt.Sprintf("cumulative risk %.0f crossed the revoke threshold, but this process has no credentials.Store configured, nothing was revoked", total)
		case revoked == 0:
			detail = fmt.Sprintf("cumulative risk %.0f crossed the revoke threshold, agent had no active credentials to revoke", total)
		default:
			detail = fmt.Sprintf("cumulative risk %.0f crossed threshold, revoked %d active credential(s)", total, revoked)
		}
	}

	// The structured record, not just the audit line. A failure here is
	// logged into the audit detail rather than failing Observe outright,
	// same posture as everything else in this function: the containment
	// action itself already happened (or was already decided not to
	// revoke anything), a record-keeping failure alongside it is a
	// separate concern from whether the response executed.
	if m.incidents != nil {
		if _, err := m.incidents.Create(ctx, incident.Incident{
			AgentRef:    score.AgentRef,
			IncidentRef: incidentRef,
			Action:      string(action),
			RiskValue:   score.Value,
			Cumulative:  total,
			Signals:     score.Signals,
			Reason:      detail,
			CreatedAt:   time.Now(),
		}); err != nil {
			detail = detail + fmt.Sprintf(" (incident record not saved: %v)", err)
		}
	}

	return action, m.audit.Append(ctx, audit.Event{
		Action:   "monitoring." + string(action),
		AgentRef: score.AgentRef,
		Operator: "monitoring",
		Incident: incidentRef,
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
func (m *Monitor) revokeCredentials(ctx context.Context, agentRef, incidentRef string) (revoked int, configured bool, err error) {
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
		if err := m.creds.Revoke(ctx, c.ID, "monitoring", "risk score crossed the revoke threshold ("+incidentRef+")"); err != nil {
			return revoked, true, err
		}
		revoked++
	}
	return revoked, true, nil
}
