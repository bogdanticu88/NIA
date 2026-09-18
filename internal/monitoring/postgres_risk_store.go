package monitoring

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/lib/pq"

	"github.com/bogdanticu88/nia/internal/dbschema"
)

// riskSchemaSQL creates the one table PostgresRiskStore needs, same
// not-a-migration-framework posture every other PostgresX in this
// codebase takes, see internal/audit/postgres_sink.go's own comment on
// why CREATE TABLE IF NOT EXISTS is the whole migration story here too.
const riskSchemaSQL = `
CREATE TABLE IF NOT EXISTS risk_state (
	agent_ref  TEXT PRIMARY KEY,
	cumulative DOUBLE PRECISION NOT NULL DEFAULT 0,
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
`

// PostgresRiskStore is the shared RiskStore: every gateway process
// pointed at the same database observes the same running total for a
// given agent, closing the multi-replica gap InMemoryRiskStore's own
// doc comment names. Accumulate is a single UPSERT, not a
// read-then-write pair: Postgres's own row-level locking during the
// UPDATE half of the statement serializes two concurrent Accumulate
// calls for the same agent_ref, whether they come from goroutines in
// the same process or two different processes entirely, without this
// package needing to take out an explicit transaction the way
// internal/credentials.PostgresStore.Rotate or
// internal/audit.PostgresSink.Append do for their own atomicity needs.
// A running total genuinely only ever needs one statement to update
// safely, there's no multi-row invariant here to protect with a wider
// transaction.
// Pool limits. database/sql defaults to an unbounded number of open
// connections, and one NIA process now opens four separate pools
// against the same database (audit, credentials, risk state, call
// history), so an unbounded default means a handful of replicas under
// load can exhaust a stock Postgres, whose own default is 100 clients.
// That failure is worse than it sounds because it hits every store at
// once: audit appends start failing (fail-open by design, see
// docs/SECURITY_INVARIANTS.md invariant 8), risk scoring starts
// erroring, and credential verification starts returning
// infrastructure errors rather than answers.
//
// Observed rather than theorised: a live concurrency test opening 100
// simultaneous callers across two pools, with two NIA binaries already
// holding their own, hit "pq: sorry, too many clients already" and lost
// updates.
//
// Same numbers in all four constructors on purpose, duplicated rather
// than shared because there is no common database package here yet and
// inventing one for three constants is the wrong trade. If these ever
// need to differ per store, that is the moment to add one.
const (
	maxOpenConns    = 8
	maxIdleConns    = 4
	connMaxLifetime = 30 * time.Minute
)

type PostgresRiskStore struct {
	db *sql.DB
}

// NewPostgresRiskStore opens a connection pool against dsn, confirms it
// works, and ensures the schema exists before returning, same fail-fast
// posture as credentials.NewPostgresStore and audit.NewPostgresSink.
func NewPostgresRiskStore(ctx context.Context, dsn string) (*PostgresRiskStore, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("monitoring: opening postgres: %w", err)
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("monitoring: postgres unreachable: %w", err)
	}
	if err := dbschema.Apply(ctx, db, "monitoring", riskSchemaSQL); err != nil {
		db.Close()
		return nil, err
	}
	db.SetMaxOpenConns(maxOpenConns)
	db.SetMaxIdleConns(maxIdleConns)
	db.SetConnMaxLifetime(connMaxLifetime)
	return &PostgresRiskStore{db: db}, nil
}

// Close releases the underlying connection pool. Neither cmd/gateway
// nor cmd/api calls this today, the process runs until it exits, tests
// do, same reasoning as PostgresStore.Close and PostgresSink.Close.
func (s *PostgresRiskStore) Close() error {
	return s.db.Close()
}

func (s *PostgresRiskStore) Accumulate(ctx context.Context, agentRef string, value float64) (float64, error) {
	var total float64
	err := s.db.QueryRowContext(ctx,
		`INSERT INTO risk_state (agent_ref, cumulative, updated_at)
		 VALUES ($1, $2, now())
		 ON CONFLICT (agent_ref) DO UPDATE
		     SET cumulative = risk_state.cumulative + EXCLUDED.cumulative, updated_at = now()
		 RETURNING cumulative`,
		agentRef, value,
	).Scan(&total)
	if err != nil {
		return 0, fmt.Errorf("monitoring: accumulate: %w", err)
	}
	return total, nil
}

func (s *PostgresRiskStore) Get(ctx context.Context, agentRef string) (float64, error) {
	var total float64
	err := s.db.QueryRowContext(ctx, `SELECT cumulative FROM risk_state WHERE agent_ref = $1`, agentRef).Scan(&total)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, nil
		}
		return 0, fmt.Errorf("monitoring: get: %w", err)
	}
	return total, nil
}

// Reset deletes agentRef's row outright rather than zeroing it in
// place, so "never observed" and "reset by a kill" read back
// identically, the same choice InMemoryRiskStore's delete makes and
// exactly what Get above already expects (no row means 0).
func (s *PostgresRiskStore) Reset(ctx context.Context, agentRef string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM risk_state WHERE agent_ref = $1`, agentRef); err != nil {
		return fmt.Errorf("monitoring: reset: %w", err)
	}
	return nil
}

func (s *PostgresRiskStore) TrackedAgents(ctx context.Context) (int, error) {
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM risk_state`).Scan(&n); err != nil {
		return 0, fmt.Errorf("monitoring: tracked agents: %w", err)
	}
	return n, nil
}

var _ RiskStore = (*PostgresRiskStore)(nil)
