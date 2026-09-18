package risk

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "github.com/lib/pq"
)

// historySchemaSQL creates the four tables PostgresCallHistory needs,
// same not-a-migration-framework posture every other PostgresX in this
// codebase takes, see internal/audit/postgres_sink.go's own comment.
//
// agent_calls is the only one that grows with traffic rather than with
// distinct behaviour, and Observe prunes it to the window on every call
// for the agent it just saw, so it stays bounded by "calls in flight
// inside the window" rather than by total history.
const historySchemaSQL = `
CREATE TABLE IF NOT EXISTS agent_tool_history (
	agent_ref  TEXT NOT NULL,
	tool       TEXT NOT NULL,
	first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
	PRIMARY KEY (agent_ref, tool)
);
CREATE TABLE IF NOT EXISTS agent_transition_history (
	agent_ref  TEXT NOT NULL,
	prev_tool  TEXT NOT NULL,
	next_tool  TEXT NOT NULL,
	first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
	PRIMARY KEY (agent_ref, prev_tool, next_tool)
);
CREATE TABLE IF NOT EXISTS agent_last_tool (
	agent_ref TEXT PRIMARY KEY,
	tool      TEXT NOT NULL,
	at        TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS agent_calls (
	id        BIGSERIAL PRIMARY KEY,
	agent_ref TEXT NOT NULL,
	tool      TEXT NOT NULL,
	at        TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS agent_calls_ref_at_idx ON agent_calls (agent_ref, at);
`

// PostgresCallHistory is the shared CallHistory: every gateway process
// pointed at the same database sees one behavioural baseline per agent
// instead of its own.
//
// This is the other half of the distributed-state work
// internal/monitoring.PostgresRiskStore started. That one made the
// cumulative risk total shared; this one makes the signals that total
// is built from shared. Without it, three replicas meant the same tool
// scored novel_tool up to three times and every restart made the whole
// catalog look novel again, so a correctly shared total was being fed
// by inputs that were neither shared nor stable.
type PostgresCallHistory struct {
	db *sql.DB
}

// NewPostgresCallHistory opens a pool against dsn, confirms it works,
// and ensures the schema exists before returning, same fail-fast
// posture as every other PostgresX constructor here.
func NewPostgresCallHistory(ctx context.Context, dsn string) (*PostgresCallHistory, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("risk: opening postgres: %w", err)
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("risk: postgres unreachable: %w", err)
	}
	if _, err := db.ExecContext(ctx, historySchemaSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("risk: creating call history schema: %w", err)
	}
	return &PostgresCallHistory{db: db}, nil
}

func (h *PostgresCallHistory) Close() error { return h.db.Close() }

// Observe records the call and reports what the history looked like
// just before it, in one transaction.
//
// The transaction takes a per-agent advisory lock first. Without it,
// two concurrent calls for the same agent, in the same process or in
// different ones, can both find the tool absent and both report
// NovelTool, double-counting the signal, which is the same race
// InMemoryCallHistory's mutex closes within one process. An advisory
// lock rather than SELECT ... FOR UPDATE because there is no single row
// that always exists to lock: an agent's very first call has no row in
// any of these tables yet.
func (h *PostgresCallHistory) Observe(ctx context.Context, agentRef, tool string, at time.Time, window time.Duration) (Observation, error) {
	tx, err := h.db.BeginTx(ctx, nil)
	if err != nil {
		return Observation{}, fmt.Errorf("risk: history: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, agentRef); err != nil {
		return Observation{}, fmt.Errorf("risk: history: locking %s: %w", agentRef, err)
	}

	var obs Observation

	res, err := tx.ExecContext(ctx,
		`INSERT INTO agent_tool_history (agent_ref, tool, first_seen) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`,
		agentRef, tool, at,
	)
	if err != nil {
		return Observation{}, fmt.Errorf("risk: history: recording tool: %w", err)
	}
	if n, err := res.RowsAffected(); err == nil && n == 1 {
		obs.NovelTool = true
	}

	var prevTool string
	err = tx.QueryRowContext(ctx, `SELECT tool FROM agent_last_tool WHERE agent_ref = $1`, agentRef).Scan(&prevTool)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		// First call this agent has ever made, there is no transition
		// to judge, which is a different thing from a transition that
		// is merely familiar, see Observation.NovelTransition.
	case err != nil:
		return Observation{}, fmt.Errorf("risk: history: reading last tool: %w", err)
	case prevTool == tool:
		// A repeat of the same tool is not a new ordering, see
		// Observation.NovelTransition. Not recorded either, so a later
		// A -> A -> B still sees A -> B as the transition it is.
	default:
		res, err := tx.ExecContext(ctx,
			`INSERT INTO agent_transition_history (agent_ref, prev_tool, next_tool, first_seen) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING`,
			agentRef, prevTool, tool, at,
		)
		if err != nil {
			return Observation{}, fmt.Errorf("risk: history: recording transition: %w", err)
		}
		if n, err := res.RowsAffected(); err == nil && n == 1 {
			obs.NovelTransition = true
		}
	}

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO agent_last_tool (agent_ref, tool, at) VALUES ($1, $2, $3)
		 ON CONFLICT (agent_ref) DO UPDATE SET tool = EXCLUDED.tool, at = EXCLUDED.at`,
		agentRef, tool, at,
	); err != nil {
		return Observation{}, fmt.Errorf("risk: history: updating last tool: %w", err)
	}

	if window > 0 {
		cutoff := at.Add(-window)
		if _, err := tx.ExecContext(ctx, `DELETE FROM agent_calls WHERE agent_ref = $1 AND at <= $2`, agentRef, cutoff); err != nil {
			return Observation{}, fmt.Errorf("risk: history: pruning calls: %w", err)
		}
		if err := tx.QueryRowContext(ctx,
			`SELECT count(*) FROM agent_calls WHERE agent_ref = $1 AND at > $2`, agentRef, cutoff,
		).Scan(&obs.RecentCalls); err != nil {
			return Observation{}, fmt.Errorf("risk: history: counting recent calls: %w", err)
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO agent_calls (agent_ref, tool, at) VALUES ($1, $2, $3)`, agentRef, tool, at,
		); err != nil {
			return Observation{}, fmt.Errorf("risk: history: recording call: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return Observation{}, fmt.Errorf("risk: history: commit: %w", err)
	}
	return obs, nil
}

var _ CallHistory = (*PostgresCallHistory)(nil)
