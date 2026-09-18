package registry

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "github.com/lib/pq"

	"github.com/bogdanticu88/nia/internal/identity"
)

// agentSchemaSQL creates the one table PostgresAgentRegistry needs, same
// not-a-migration-framework posture every other PostgresX here takes,
// see internal/audit/postgres_sink.go's own comment.
//
// killed_at is nullable because it is genuinely absent for an agent
// that has never been killed, and a zero timestamp would read back as a
// kill in 0001, which is exactly the kind of thing an incident review
// should never have to second-guess.
const agentSchemaSQL = `
CREATE TABLE IF NOT EXISTS agents (
	ref           TEXT PRIMARY KEY,
	display_name  TEXT NOT NULL DEFAULT '',
	owner         TEXT NOT NULL DEFAULT '',
	business_unit TEXT NOT NULL DEFAULT '',
	assurance     INTEGER NOT NULL DEFAULT 0,
	state         TEXT NOT NULL DEFAULT 'active',
	purpose       TEXT NOT NULL DEFAULT '',
	registered_at TIMESTAMPTZ NOT NULL,
	kill_incident TEXT NOT NULL DEFAULT '',
	killed_at     TIMESTAMPTZ,
	killed_by     TEXT NOT NULL DEFAULT ''
);
`

// Pool limits, same numbers and reasoning as every other PostgresX
// constructor here, see internal/audit/postgres_sink.go's own block.
const (
	maxOpenConns    = 8
	maxIdleConns    = 4
	connMaxLifetime = 30 * time.Minute
)

// PostgresAgentRegistry is the shared AgentRegistry. Until it existed,
// the NHI inventory was a map in one process, which had a consequence
// worth naming plainly: a second cmd/api replica returned 404 for an
// agent the first had registered, and `niactl list` showed a different
// inventory depending on which replica answered. Enforcement never
// depended on it (kill state is read live from the policy client, see
// cmd/api's handleGetAgent), so this was an inventory and
// investigability gap rather than an authorization one, but "the
// inventory disagrees with itself" is not a property a control plane
// gets to have.
type PostgresAgentRegistry struct {
	db *sql.DB
}

func NewPostgresAgentRegistry(ctx context.Context, dsn string) (*PostgresAgentRegistry, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("registry: opening postgres: %w", err)
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("registry: postgres unreachable: %w", err)
	}
	if _, err := db.ExecContext(ctx, agentSchemaSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("registry: creating agents schema: %w", err)
	}
	db.SetMaxOpenConns(maxOpenConns)
	db.SetMaxIdleConns(maxIdleConns)
	db.SetConnMaxLifetime(connMaxLifetime)
	return &PostgresAgentRegistry{db: db}, nil
}

func (r *PostgresAgentRegistry) Close() error { return r.db.Close() }

// Register inserts the agent, relying on the primary key rather than a
// read-then-write to detect a duplicate. That matters across replicas:
// checking for existence and then inserting leaves a window where two
// replicas both see "not registered" and both insert, and only one of
// those can win. Here the database decides, and the loser gets
// ErrAlreadyRegistered, the same error the in-memory implementation
// returns for the same situation.
func (r *PostgresAgentRegistry) Register(ctx context.Context, agent identity.AgentRef) error {
	if agent.RegisteredAt.IsZero() {
		agent.RegisteredAt = time.Now()
	}
	if agent.State == "" {
		agent.State = identity.StateActive
	}
	res, err := r.db.ExecContext(ctx,
		`INSERT INTO agents (ref, display_name, owner, business_unit, assurance, state, purpose, registered_at, kill_incident, killed_at, killed_by)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT (ref) DO NOTHING`,
		agent.Ref, agent.DisplayName, agent.Owner, agent.BusinessUnit, int(agent.Assurance),
		string(agent.State), agent.Purpose, agent.RegisteredAt, agent.KillIncident, agent.KilledAt, agent.KilledBy,
	)
	if err != nil {
		return fmt.Errorf("registry: registering %s: %w", agent.Ref, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("registry: registering %s: %w", agent.Ref, err)
	}
	if n == 0 {
		return ErrAlreadyRegistered
	}
	return nil
}

func (r *PostgresAgentRegistry) Get(ctx context.Context, ref string) (identity.AgentRef, error) {
	row := r.db.QueryRowContext(ctx, agentSelectColumns+` FROM agents WHERE ref = $1`, ref)
	agent, err := scanAgent(row)
	if errors.Is(err, sql.ErrNoRows) {
		return identity.AgentRef{}, ErrNotFound
	}
	if err != nil {
		return identity.AgentRef{}, fmt.Errorf("registry: getting %s: %w", ref, err)
	}
	return agent, nil
}

func (r *PostgresAgentRegistry) List(ctx context.Context) ([]identity.AgentRef, error) {
	rows, err := r.db.QueryContext(ctx, agentSelectColumns+` FROM agents ORDER BY registered_at ASC, ref ASC`)
	if err != nil {
		return nil, fmt.Errorf("registry: listing agents: %w", err)
	}
	defer rows.Close()

	out := make([]identity.AgentRef, 0)
	for rows.Next() {
		agent, err := scanAgent(rows)
		if err != nil {
			return nil, fmt.Errorf("registry: listing agents: %w", err)
		}
		out = append(out, agent)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("registry: listing agents: %w", err)
	}
	return out, nil
}

// SetState updates the cached lifecycle state. killed_at is set only on
// the transition into killed and deliberately not cleared on the way
// out: when an agent is restored, when it was last killed is still true
// and still worth having during a review.
func (r *PostgresAgentRegistry) SetState(ctx context.Context, ref string, state identity.LifecycleState) error {
	var res sql.Result
	var err error
	if state == identity.StateKilled {
		res, err = r.db.ExecContext(ctx, `UPDATE agents SET state = $1, killed_at = $2 WHERE ref = $3`, string(state), time.Now(), ref)
	} else {
		res, err = r.db.ExecContext(ctx, `UPDATE agents SET state = $1 WHERE ref = $2`, string(state), ref)
	}
	if err != nil {
		return fmt.Errorf("registry: setting state for %s: %w", ref, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("registry: setting state for %s: %w", ref, err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

const agentSelectColumns = `SELECT ref, display_name, owner, business_unit, assurance, state, purpose, registered_at, kill_incident, killed_at, killed_by`

type rowScanner interface {
	Scan(dest ...any) error
}

func scanAgent(row rowScanner) (identity.AgentRef, error) {
	var a identity.AgentRef
	var assurance int
	var state string
	var killedAt sql.NullTime
	if err := row.Scan(
		&a.Ref, &a.DisplayName, &a.Owner, &a.BusinessUnit, &assurance,
		&state, &a.Purpose, &a.RegisteredAt, &a.KillIncident, &killedAt, &a.KilledBy,
	); err != nil {
		return identity.AgentRef{}, err
	}
	a.Assurance = identity.Assurance(assurance)
	a.State = identity.LifecycleState(state)
	if killedAt.Valid {
		t := killedAt.Time
		a.KilledAt = &t
	}
	return a, nil
}

var _ AgentRegistry = (*PostgresAgentRegistry)(nil)
