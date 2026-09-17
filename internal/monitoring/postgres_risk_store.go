package monitoring

import (
	"context"
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
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
	if _, err := db.ExecContext(ctx, riskSchemaSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("monitoring: creating risk_state schema: %w", err)
	}
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
