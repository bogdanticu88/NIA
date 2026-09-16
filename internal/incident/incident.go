// Package incident is the structured record of a containment decision:
// an agent's risk crossed a threshold, internal/monitoring decided to
// flag, revoke, or kill, and this is what that decision actually looked
// like at the moment it happened, not a description reconstructed later
// by scraping internal/audit for events that happen to share a free-text
// incident string.
//
// internal/audit already records that something happened
// ("monitoring.kill", agent X, detail "cumulative risk 24 crossed
// threshold"). This package records what it was a response to: the
// exact risk value and signals that triggered it, the cumulative total
// at that moment, and the action taken, one record per containment
// decision rather than one audit line per side effect of it. An
// incident review starts here, not by grepping the audit trail for a
// string an operator happened to pass on the CLI.
//
// This intentionally does not carry a blast-radius snapshot yet.
// internal/graph can compute reachability today, but nothing populates
// the graph automatically from what's already known elsewhere
// (registered agents, granted tools, issued credentials), so a snapshot
// taken at containment time would be empty for any agent an operator
// hasn't also hand-built into the graph, which would be worse than not
// showing one. That's the next honest step once the graph is populated
// automatically, not something to fake here with a hardcoded shape.
package incident

import (
	"context"
	"errors"
	"time"

	"github.com/bogdanticu88/nia/internal/risk"
)

// Incident is one containment decision. AgentRef is who it's about,
// IncidentRef is the caller-supplied correlator (an operator's "INC-001"
// on a manual kill, or the gateway's own "auto-risk-<nanos>" for a
// monitoring-triggered one, see cmd/gateway's observe), Action is
// "flag", "revoke", or "kill" (kept as a plain string rather than
// importing internal/monitoring's Action type, monitoring depends on
// this package to create records, not the other way around, an import
// cycle would follow if this package depended back on monitoring for
// one type alias).
type Incident struct {
	ID          string
	AgentRef    string
	IncidentRef string
	Action      string
	RiskValue   float64
	Cumulative  float64
	Signals     []risk.Signal
	Reason      string
	CreatedAt   time.Time
}

var ErrNotFound = errors.New("incident: not found")

// Store is where incident records live. Create is called once per
// containment decision, by internal/monitoring, immediately after the
// decision is made; Get and List are the read side cmd/gateway's HTTP
// handlers and niactl incident use.
type Store interface {
	Create(ctx context.Context, in Incident) (Incident, error)
	Get(ctx context.Context, id string) (Incident, error)
	// List returns incidents oldest first, optionally filtered to one
	// agent (agentRef == "" means every agent), capped at limit (<= 0
	// means every matching incident).
	List(ctx context.Context, agentRef string, limit int) ([]Incident, error)
}
