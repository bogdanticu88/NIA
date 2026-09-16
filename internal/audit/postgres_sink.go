package audit

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/lib/pq"
)

// schemaSQL creates the one table PostgresSink needs if it isn't there
// already. Deliberately not a migration framework, this table's shape
// has never changed and doesn't need to be versioned separately from
// the code that reads and writes it, CREATE TABLE IF NOT EXISTS run
// once at construction is the whole migration story for now. If that
// stops being true, this is the first thing to replace.
const schemaSQL = `
CREATE TABLE IF NOT EXISTS audit_events (
	id        BIGSERIAL PRIMARY KEY,
	action    TEXT NOT NULL,
	agent_ref TEXT NOT NULL DEFAULT '',
	operator  TEXT NOT NULL DEFAULT '',
	incident  TEXT NOT NULL DEFAULT '',
	detail    TEXT NOT NULL DEFAULT '',
	at        TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_events_agent_ref_idx ON audit_events (agent_ref, at);
CREATE INDEX IF NOT EXISTS audit_events_at_idx ON audit_events (at);
`

// recentUnboundedCap is what Recent asks Postgres for when the caller
// passes n <= 0, meaning "no limit" per the Store doc comment. Actually
// unbounded would let one bad call scan and return the entire table;
// this is a limit high enough that nothing in this codebase's own
// callers (cmd/api caps its own HTTP-facing limit well below this, see
// auditLimitMax in cmd/api/main.go) will ever hit it.
const recentUnboundedCap = 100_000

// PostgresSink is the real Store: events survive a restart and are
// visible to every process pointed at the same database, which is the
// entire reason InMemorySink was never going to be the last word here.
// Built on database/sql with lib/pq rather than a heavier driver on
// purpose, this package needs exactly three query shapes (insert,
// ordered scan, filtered scan), nothing here calls for prepared
// statement caching, a tuned pool, or anything else a fancier driver
// would buy.
type PostgresSink struct {
	db *sql.DB
}

// NewPostgresSink opens a connection pool against dsn, confirms it
// actually works, and ensures the schema exists, all before returning.
// Same fail-fast-at-startup choice policy.FromEnv makes for a missing
// signing key: a control plane that starts clean and then fails on its
// first audit write is a worse failure mode than one that never started
// at all.
func NewPostgresSink(ctx context.Context, dsn string) (*PostgresSink, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("audit: opening postgres: %w", err)
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("audit: postgres unreachable: %w", err)
	}
	if _, err := db.ExecContext(ctx, schemaSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("audit: creating audit_events schema: %w", err)
	}
	return &PostgresSink{db: db}, nil
}

// Close releases the underlying connection pool. Neither cmd/api nor
// cmd/gateway calls this today, both run until the process exits, but
// tests do, one fresh connection per test case would otherwise leak.
func (s *PostgresSink) Close() error {
	return s.db.Close()
}

func (s *PostgresSink) Append(ctx context.Context, evt Event) error {
	if evt.At.IsZero() {
		evt.At = time.Now()
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO audit_events (action, agent_ref, operator, incident, detail, at) VALUES ($1, $2, $3, $4, $5, $6)`,
		evt.Action, evt.AgentRef, evt.Operator, evt.Incident, evt.Detail, evt.At,
	)
	if err != nil {
		return fmt.Errorf("audit: append: %w", err)
	}
	return nil
}

// Recent returns up to n most recent events, oldest first, matching
// InMemorySink.Recent and the Store doc comment. Fetches newest-first
// with a LIMIT, the index this needs, then reverses in Go rather than
// asking Postgres to sort the whole table ascending just to hand back
// the last few rows.
func (s *PostgresSink) Recent(ctx context.Context, n int) ([]Event, error) {
	if n <= 0 {
		n = recentUnboundedCap
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT action, agent_ref, operator, incident, detail, at FROM audit_events ORDER BY at DESC, id DESC LIMIT $1`,
		n,
	)
	if err != nil {
		return nil, fmt.Errorf("audit: recent: %w", err)
	}
	defer rows.Close()
	events, err := scanEvents(rows)
	if err != nil {
		return nil, err
	}
	reverseEvents(events)
	return events, nil
}

func (s *PostgresSink) ForAgent(ctx context.Context, agentRef string) ([]Event, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT action, agent_ref, operator, incident, detail, at FROM audit_events WHERE agent_ref = $1 ORDER BY at ASC, id ASC`,
		agentRef,
	)
	if err != nil {
		return nil, fmt.Errorf("audit: for agent: %w", err)
	}
	defer rows.Close()
	return scanEvents(rows)
}

func scanEvents(rows *sql.Rows) ([]Event, error) {
	var out []Event
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.Action, &e.AgentRef, &e.Operator, &e.Incident, &e.Detail, &e.At); err != nil {
			return nil, fmt.Errorf("audit: scanning row: %w", err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit: iterating rows: %w", err)
	}
	return out, nil
}

func reverseEvents(events []Event) {
	for i, j := 0, len(events)-1; i < j; i, j = i+1, j-1 {
		events[i], events[j] = events[j], events[i]
	}
}

var (
	_ Sink  = (*PostgresSink)(nil)
	_ Store = (*PostgresSink)(nil)
)
