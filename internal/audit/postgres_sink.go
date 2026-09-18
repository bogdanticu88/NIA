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

// chainSchemaSQL is the hash-chain addition to a table that may
// already exist from before this feature: ADD COLUMN IF NOT EXISTS
// rather than a fresh CREATE TABLE, this is exactly the "first thing
// to replace" schemaSQL's own doc comment warned about the day this
// table's shape needed to change. A row written before this migration
// ran keeps hash and prev_hash empty, see chain.go's own doc comment
// on why Verify treats that as "predates chaining," excluded rather
// than either trusted or flagged.
//
// audit_chain_state is a one-row table, not a column on audit_events,
// because Append needs a lockable row to serialize concurrent writers
// against, `SELECT ... FOR UPDATE` on a query that might return zero
// rows (an empty or all-legacy audit_events table) can't lock anything.
// This table always has exactly one row, enforced by the boolean
// primary key plus the CHECK, so there's always something to lock,
// from the very first Append this process or any other process sharing
// this database ever makes.
const chainSchemaSQL = `
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS hash TEXT NOT NULL DEFAULT '';
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS prev_hash TEXT NOT NULL DEFAULT '';
CREATE TABLE IF NOT EXISTS audit_chain_state (
	id        BOOLEAN PRIMARY KEY DEFAULT TRUE,
	last_hash TEXT NOT NULL,
	CONSTRAINT audit_chain_state_singleton CHECK (id)
);
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
	if _, err := db.ExecContext(ctx, chainSchemaSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("audit: creating audit chain schema: %w", err)
	}
	// Seed the singleton chain-state row with GenesisHash if this is
	// the very first time this feature has run against this database,
	// ON CONFLICT DO NOTHING so a second process starting up against
	// the same database (cmd/api and cmd/gateway both point at one
	// audit database, see docker-compose.yml) doesn't clobber a chain
	// the first process already started.
	if _, err := db.ExecContext(ctx,
		`INSERT INTO audit_chain_state (id, last_hash) VALUES (TRUE, $1) ON CONFLICT (id) DO NOTHING`,
		GenesisHash,
	); err != nil {
		db.Close()
		return nil, fmt.Errorf("audit: seeding chain state: %w", err)
	}
	return &PostgresSink{db: db}, nil
}

// Close releases the underlying connection pool. Neither cmd/api nor
// cmd/gateway calls this today, both run until the process exits, but
// tests do, one fresh connection per test case would otherwise leak.
func (s *PostgresSink) Close() error {
	return s.db.Close()
}

// Append writes evt and extends the hash chain in the same
// transaction. `SELECT last_hash ... FOR UPDATE` on the singleton
// audit_chain_state row locks out any other concurrent Append,
// including one from a different process sharing this database, until
// this transaction commits or rolls back, which is what makes the
// chain correct under concurrent writers rather than merely correct in
// a single-process test: two goroutines, or two processes, appending
// at the same moment cannot both read the same "last hash" and produce
// two events claiming the same prev_hash, one of them blocks until the
// other's transaction finishes and the locked row reflects the new
// last_hash.
func (s *PostgresSink) Append(ctx context.Context, evt Event) error {
	if evt.At.IsZero() {
		evt.At = time.Now()
	}
	// TIMESTAMPTZ stores microsecond precision and rounds to the
	// nearest microsecond on insert, it does not truncate, so a Go
	// time.Time's nanosecond remainder can round either up or down
	// depending on its exact value. Truncating here, before both the
	// hash is computed and the row is inserted, means the value this
	// process hashes and the value Postgres actually stores are
	// already identical, nothing is left for Postgres's own rounding
	// to disagree with. Without this, canonicalize's own truncation
	// (see chain.go) would floor the value at verification time while
	// Postgres had rounded it up at write time, and every event whose
	// nanosecond remainder happened to round up would look "modified"
	// the moment it was read back, not because anything was tampered
	// with.
	evt.At = evt.At.UTC().Truncate(time.Microsecond)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("audit: append: beginning transaction: %w", err)
	}
	defer tx.Rollback() // no-op once Commit has succeeded

	var prevHash string
	if err := tx.QueryRowContext(ctx, `SELECT last_hash FROM audit_chain_state WHERE id = TRUE FOR UPDATE`).Scan(&prevHash); err != nil {
		return fmt.Errorf("audit: append: locking chain state: %w", err)
	}

	hash := chainHash(evt, prevHash)

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO audit_events (action, agent_ref, operator, incident, detail, at, hash, prev_hash) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		evt.Action, evt.AgentRef, evt.Operator, evt.Incident, evt.Detail, evt.At, hash, prevHash,
	); err != nil {
		return fmt.Errorf("audit: append: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `UPDATE audit_chain_state SET last_hash = $1 WHERE id = TRUE`, hash); err != nil {
		return fmt.Errorf("audit: append: updating chain state: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("audit: append: committing: %w", err)
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

// Chain returns every row in audit_events in insertion order (by id,
// the table's own serial primary key, which is exactly the storage
// layer's real append order, not the caller-supplied At timestamp) with
// its hash-chain metadata. StartsAtGenesis is always true: unlike
// InMemorySink, this table has no capacity eviction, whatever rows
// exist are the complete on-disk history, minus anything an attacker
// or operator explicitly deleted, which is exactly what Verify's
// prev_hash check is there to catch.
func (s *PostgresSink) Chain(ctx context.Context) (Chain, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, action, agent_ref, operator, incident, detail, at, hash, prev_hash FROM audit_events ORDER BY id ASC`,
	)
	if err != nil {
		return Chain{}, fmt.Errorf("audit: chain: %w", err)
	}
	defer rows.Close()

	var out []ChainedEvent
	for rows.Next() {
		var ce ChainedEvent
		if err := rows.Scan(&ce.Seq, &ce.Action, &ce.AgentRef, &ce.Operator, &ce.Incident, &ce.Detail, &ce.At, &ce.Hash, &ce.PrevHash); err != nil {
			return Chain{}, fmt.Errorf("audit: chain: scanning row: %w", err)
		}
		out = append(out, ce)
	}
	if err := rows.Err(); err != nil {
		return Chain{}, fmt.Errorf("audit: chain: iterating rows: %w", err)
	}
	// The tip lives in audit_chain_state, a different table from the
	// events, which is the whole point: an attacker who truncates
	// audit_events has to know to rewrite this row too, see Chain.Tip's
	// own doc comment. A missing row (a database predating the chain
	// migration that somehow never ran NewPostgresSink) leaves Tip
	// empty and Verify skips the check rather than reporting a false
	// break.
	var tip string
	if err := s.db.QueryRowContext(ctx, `SELECT last_hash FROM audit_chain_state WHERE id = TRUE`).Scan(&tip); err != nil && err != sql.ErrNoRows {
		return Chain{}, fmt.Errorf("audit: chain: reading chain tip: %w", err)
	}
	return Chain{Events: out, StartsAtGenesis: true, Tip: tip}, nil
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
	_ Sink    = (*PostgresSink)(nil)
	_ Store   = (*PostgresSink)(nil)
	_ Chained = (*PostgresSink)(nil)
)
