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
// documented here rather than left to guesswork.
//
// Where that running total actually lives is RiskStore's job, not
// this type's, see risk_store.go. The default, NewMonitor, keeps it in
// an InMemoryRiskStore, private to whatever process constructs this
// Monitor, the original behavior and still correct for a single
// process or a test. cmd/gateway builds a Monitor with
// NewMonitorWithRiskStore instead, backed by whatever
// monitoring.RiskStoreFromEnv returns, so the total is shared across
// every gateway replica pointed at the same store when
// NIA_RISK_DATABASE_URL is set, see that function's own doc comment
// and docs/ARCHITECTURE.md's "Distributed state" section for why this
// matters: a second gateway replica with its own separate view of an
// agent's cumulative risk is exactly the kind of state fragmentation
// an attacker spreading calls across replicas could otherwise use to
// keep any single replica's own view under the kill threshold forever.
type Monitor struct {
	thresholds Threshold
	policy     policy.Client
	creds      credentials.Store // optional, nil means ActionRevoke is a documented no-op, see revokeCredentials
	incidents  incident.Store    // optional, nil means no structured incident record is created, only the audit event
	audit      audit.Sink
	risk       RiskStore
}

// NewMonitor builds a Monitor backed by an InMemoryRiskStore, the
// original process-local behavior, correct for a single process or a
// test that isn't specifically exercising the shared, multi-replica
// case. creds may be nil: a deployment that hasn't wired a
// credentials.Store into whatever process runs this (cmd/gateway
// doesn't have one today, see cmd/gateway's own doc comment) still gets
// flag and kill behavior, ActionRevoke degrades to a no-op that says so
// in its own audit detail rather than silently pretending to have
// revoked something. incidents may also be nil: a deployment that
// hasn't wired an incident.Store in still gets the audit event Observe
// always writes, it just doesn't get a structured Incident record
// alongside it, see this file's own package doc comment on why the two
// are different things.
func NewMonitor(t Threshold, p policy.Client, creds credentials.Store, incidents incident.Store, a audit.Sink) *Monitor {
	return NewMonitorWithRiskStore(t, p, creds, incidents, a, NewInMemoryRiskStore())
}

// NewMonitorWithRiskStore is NewMonitor with an explicit RiskStore,
// what cmd/gateway actually calls, passing whatever
// monitoring.RiskStoreFromEnv resolved (in-memory by default, Postgres-
// backed and shared across replicas when NIA_RISK_DATABASE_URL is set).
func NewMonitorWithRiskStore(t Threshold, p policy.Client, creds credentials.Store, incidents incident.Store, a audit.Sink, risk RiskStore) *Monitor {
	return &Monitor{thresholds: t, policy: p, creds: creds, incidents: incidents, audit: a, risk: risk}
}

// CumulativeRisk returns the current running total for an agent, 0 if
// Observe has never been called for it or if it was last reset by a
// kill. Exported so callers other than the gateway's own request loop,
// an incident report or a CLI command inspecting an agent's current
// risk, can read the same number Observe itself is comparing against
// the thresholds, rather than each keeping their own view of it. Takes
// a context and can fail now that the total may live in Postgres rather
// than a process-local map, see RiskStore.Get.
func (m *Monitor) CumulativeRisk(ctx context.Context, agentRef string) (float64, error) {
	return m.risk.Get(ctx, agentRef)
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
func (m *Monitor) TrackedAgents(ctx context.Context) (int, error) {
	return m.risk.TrackedAgents(ctx)
}

// Observe takes a risk score and decides + executes a response. Returns
// the action taken so the caller (typically the gateway's request loop)
// can log or surface it. incidentRef is the caller-supplied correlator,
// an operator's "INC-001" on a manual kill or the gateway's own
// "auto-risk-<nanos>", it's carried into both the audit event and, when
// this Monitor has an incident.Store configured, the structured
// Incident record Observe creates for any action beyond ActionNone.
func (m *Monitor) Observe(ctx context.Context, score risk.Score, incidentRef string) (Action, error) {
	total, err := m.risk.Accumulate(ctx, score.AgentRef, score.Value)
	if err != nil {
		return ActionNone, fmt.Errorf("monitoring: accumulating risk: %w", err)
	}

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
		// forever, see this type's own doc comment. Same fail-open
		// posture as the credential revocation just below: the kill
		// itself already succeeded and is what actually matters, a
		// failure clearing the risk store afterward is folded into the
		// audit detail rather than turned into a failed Observe call.
		var resetNote string
		if err := m.risk.Reset(ctx, score.AgentRef); err != nil {
			resetNote = fmt.Sprintf(", but resetting risk history failed: %v", err)
		}
		// Convergence: a kill means credential state = REVOKED too, not
		// just the policy sentinel, see docs/ARCHITECTURE.md's "State
		// convergence" section. Before this pass, ActionKill only ever
		// touched internal/policy, an agent's credentials kept reporting
		// Active forever even though every authorization check already
		// denied them, the exact gap the phase 8 demo surfaced. The
		// kill itself already succeeded above and is what actually
		// matters; a revoke failure here is folded into the audit
		// detail rather than turned into a failed Observe call, same
		// fail-open posture as everything else that runs after the
		// containment action itself.
		revoked, configured, revokeErr := m.revokeCredentials(ctx, score.AgentRef, incidentRef)
		switch {
		case revokeErr != nil:
			detail = fmt.Sprintf("cumulative risk %.0f crossed threshold, killed, but revoking credentials failed: %v%s", total, revokeErr, resetNote)
		case !configured:
			detail = fmt.Sprintf("cumulative risk %.0f crossed threshold, killed, but this process has no credentials.Store configured, credentials were not revoked%s", total, resetNote)
		default:
			detail = fmt.Sprintf("cumulative risk %.0f crossed threshold, killed, revoked %d active credential(s)%s", total, revoked, resetNote)
		}
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
