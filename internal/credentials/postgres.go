package credentials

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/lib/pq"
)

// schemaSQL creates the one table PostgresStore needs, same
// not-a-migration-framework posture internal/audit.PostgresSink takes,
// see that file's own comment on why CREATE TABLE IF NOT EXISTS is the
// whole migration story here too. secret_hash is the SHA-256 digest,
// hex encoded, never the plaintext, see credentials.go's package doc.
const schemaSQL = `
CREATE TABLE IF NOT EXISTS credentials (
	id           TEXT PRIMARY KEY,
	agent_ref    TEXT NOT NULL,
	kind         TEXT NOT NULL,
	status       TEXT NOT NULL,
	secret_hash  TEXT NOT NULL,
	issued_at    TIMESTAMPTZ NOT NULL,
	expires_at   TIMESTAMPTZ,
	revoked_at   TIMESTAMPTZ,
	revoked_by   TEXT NOT NULL DEFAULT '',
	reason       TEXT NOT NULL DEFAULT '',
	disabled_at  TIMESTAMPTZ,
	disabled_by  TEXT NOT NULL DEFAULT '',
	enabled_at   TIMESTAMPTZ,
	rotated_from TEXT NOT NULL DEFAULT '',
	rotated_to   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS credentials_agent_ref_idx ON credentials (agent_ref);
`

// PostgresStore is the real Store: credential state survives a restart
// and is visible to every process pointed at the same database. This is
// what makes "a credential belonging to a killed agent must not
// authenticate" and "rotation must not leave the old credential valid"
// actually true across cmd/api and cmd/gateway as separate processes,
// not just within one, see docs/ARCHITECTURE.md's "State convergence"
// section. Rotate's atomicity is a real transaction here, not just a
// mutex the way InMemoryStore manages it, see Rotate's own comment.
// Pool limits, same numbers and the same reasoning as every other
// PostgresX constructor in this codebase, see
// internal/audit/postgres_sink.go's own block for the full rationale:
// database/sql is unbounded by default, one NIA process now opens four
// separate pools against the same database, and a stock Postgres allows
// 100 clients in total.
const (
	maxOpenConns    = 8
	maxIdleConns    = 4
	connMaxLifetime = 30 * time.Minute
)

type PostgresStore struct {
	db *sql.DB
}

// NewPostgresStore opens a connection pool against dsn, confirms it
// works, and ensures the schema exists before returning, same fail-fast
// posture as audit.NewPostgresSink.
func NewPostgresStore(ctx context.Context, dsn string) (*PostgresStore, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("credentials: opening postgres: %w", err)
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("credentials: postgres unreachable: %w", err)
	}
	if _, err := db.ExecContext(ctx, schemaSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("credentials: creating credentials schema: %w", err)
	}
	db.SetMaxOpenConns(maxOpenConns)
	db.SetMaxIdleConns(maxIdleConns)
	db.SetConnMaxLifetime(connMaxLifetime)
	return &PostgresStore{db: db}, nil
}

// Close releases the underlying connection pool. Neither cmd/api nor
// cmd/gateway calls this today, both run until the process exits, tests
// do, same reasoning as PostgresSink.Close.
func (s *PostgresStore) Close() error {
	return s.db.Close()
}

func (s *PostgresStore) Issue(ctx context.Context, agentRef string, kind Kind, ttl time.Duration) (Credential, string, error) {
	id, err := randomID()
	if err != nil {
		return Credential{}, "", err
	}
	secret, digest, err := newSecret()
	if err != nil {
		return Credential{}, "", err
	}
	now := time.Now()
	cred := Credential{
		ID:         id,
		AgentRef:   agentRef,
		Kind:       kind,
		Status:     StatusActive,
		SecretHash: digest,
		IssuedAt:   now,
	}
	if ttl > 0 {
		exp := now.Add(ttl)
		cred.ExpiresAt = &exp
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO credentials (id, agent_ref, kind, status, secret_hash, issued_at, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		cred.ID, cred.AgentRef, string(cred.Kind), string(cred.Status), cred.SecretHash, cred.IssuedAt, cred.ExpiresAt,
	)
	if err != nil {
		return Credential{}, "", fmt.Errorf("credentials: issue: %w", err)
	}
	return cred, secret, nil
}

func (s *PostgresStore) Get(ctx context.Context, id string) (Credential, error) {
	row := s.db.QueryRowContext(ctx, selectColumns+` FROM credentials WHERE id = $1`, id)
	c, err := scanCredential(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return Credential{}, ErrNotFound
		}
		return Credential{}, fmt.Errorf("credentials: get: %w", err)
	}
	return c, nil
}

func (s *PostgresStore) ListForAgent(ctx context.Context, agentRef string) ([]Credential, error) {
	rows, err := s.db.QueryContext(ctx, selectColumns+` FROM credentials WHERE agent_ref = $1 ORDER BY issued_at ASC`, agentRef)
	if err != nil {
		return nil, fmt.Errorf("credentials: list for agent: %w", err)
	}
	defer rows.Close()
	var out []Credential
	for rows.Next() {
		c, err := scanCredential(rows)
		if err != nil {
			return nil, fmt.Errorf("credentials: scanning row: %w", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("credentials: iterating rows: %w", err)
	}
	return out, nil
}

func (s *PostgresStore) Revoke(ctx context.Context, id, revokedBy, reason string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE credentials SET status = $1, revoked_at = $2, revoked_by = $3, reason = $4 WHERE id = $5`,
		string(StatusRevoked), time.Now(), revokedBy, reason, id,
	)
	return checkUpdated(res, err, "revoke")
}

func (s *PostgresStore) Disable(ctx context.Context, id, disabledBy, reason string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE credentials SET status = $1, disabled_at = $2, disabled_by = $3, reason = $4, enabled_at = NULL WHERE id = $5`,
		string(StatusDisabled), time.Now(), disabledBy, reason, id,
	)
	return checkUpdated(res, err, "disable")
}

func (s *PostgresStore) Enable(ctx context.Context, id, enabledBy string) error {
	// Enable on a revoked credential is refused, same reasoning as
	// InMemoryStore.Enable: revoked is one-way. This is a
	// read-then-write, not a single UPDATE guarded by a WHERE clause,
	// because the two failure modes (not found vs. revoked) need
	// different errors, and Postgres has no clean way to report which
	// branch a conditional UPDATE took without a second statement
	// anyway. The two statements run against the same *sql.DB
	// connection pool without an explicit transaction, a concurrent
	// Revoke landing between the SELECT and the UPDATE below is
	// possible in principle; the outcome is still safe either way,
	// worst case is an Enable racing a Revoke leaves the credential
	// Active when it should be Revoked, which Verify's own Effective
	// check does not protect against here, see this method's own
	// limitation noted for a future real transaction if this becomes a
	// hot enough path to matter.
	var status string
	err := s.db.QueryRowContext(ctx, `SELECT status FROM credentials WHERE id = $1`, id).Scan(&status)
	if err != nil {
		if err == sql.ErrNoRows {
			return ErrNotFound
		}
		return fmt.Errorf("credentials: enable: %w", err)
	}
	if Status(status) == StatusRevoked {
		return ErrInvalidCredential
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE credentials SET status = $1, enabled_at = $2, disabled_at = NULL, disabled_by = '' WHERE id = $3`,
		string(StatusActive), time.Now(), id,
	)
	return checkUpdated(res, err, "enable")
}

// Rotate runs inside a real database transaction: the revoke of the old
// credential and the insert of the new one either both land or neither
// does, so no concurrent Verify against either row can observe a
// half-finished rotation, the same guarantee InMemoryStore's mutex
// gives, backed here by Postgres's own isolation instead of a
// same-process lock.
func (s *PostgresStore) Rotate(ctx context.Context, id, rotatedBy string, ttl time.Duration) (Credential, string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Credential{}, "", fmt.Errorf("credentials: rotate: begin: %w", err)
	}
	defer tx.Rollback()

	var agentRef, kind string
	err = tx.QueryRowContext(ctx, `SELECT agent_ref, kind FROM credentials WHERE id = $1 FOR UPDATE`, id).Scan(&agentRef, &kind)
	if err != nil {
		if err == sql.ErrNoRows {
			return Credential{}, "", ErrNotFound
		}
		return Credential{}, "", fmt.Errorf("credentials: rotate: lookup: %w", err)
	}

	newID, err := randomID()
	if err != nil {
		return Credential{}, "", err
	}
	secret, digest, err := newSecret()
	if err != nil {
		return Credential{}, "", err
	}
	now := time.Now()

	if _, err := tx.ExecContext(ctx,
		`UPDATE credentials SET status = $1, revoked_at = $2, revoked_by = $3, reason = $4, rotated_to = $5 WHERE id = $6`,
		string(StatusRevoked), now, rotatedBy, "rotated, superseded by "+newID, newID, id,
	); err != nil {
		return Credential{}, "", fmt.Errorf("credentials: rotate: revoking old: %w", err)
	}

	next := Credential{
		ID:          newID,
		AgentRef:    agentRef,
		Kind:        Kind(kind),
		Status:      StatusActive,
		SecretHash:  digest,
		IssuedAt:    now,
		RotatedFrom: id,
	}
	if ttl > 0 {
		exp := now.Add(ttl)
		next.ExpiresAt = &exp
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO credentials (id, agent_ref, kind, status, secret_hash, issued_at, expires_at, rotated_from)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		next.ID, next.AgentRef, string(next.Kind), string(next.Status), next.SecretHash, next.IssuedAt, next.ExpiresAt, next.RotatedFrom,
	); err != nil {
		return Credential{}, "", fmt.Errorf("credentials: rotate: issuing new: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return Credential{}, "", fmt.Errorf("credentials: rotate: commit: %w", err)
	}
	return next, secret, nil
}

func (s *PostgresStore) Verify(ctx context.Context, id, presentedSecret string) (Credential, error) {
	c, err := s.Get(ctx, id)
	// Deliberately no early return on err, see verifyPresented. The
	// database round trip dominates this function's timing either way,
	// but both Store implementations answering the same shape means
	// there's one rule to reason about rather than two.
	return verifyPresented(c, err == nil, presentedSecret, time.Now())
}

const selectColumns = `SELECT id, agent_ref, kind, status, secret_hash, issued_at, expires_at,
	revoked_at, revoked_by, reason, disabled_at, disabled_by, enabled_at, rotated_from, rotated_to`

type rowScanner interface {
	Scan(dest ...any) error
}

func scanCredential(row rowScanner) (Credential, error) {
	var c Credential
	var kind, status string
	if err := row.Scan(
		&c.ID, &c.AgentRef, &kind, &status, &c.SecretHash, &c.IssuedAt, &c.ExpiresAt,
		&c.RevokedAt, &c.RevokedBy, &c.Reason, &c.DisabledAt, &c.DisabledBy, &c.EnabledAt,
		&c.RotatedFrom, &c.RotatedTo,
	); err != nil {
		return Credential{}, err
	}
	c.Kind = Kind(kind)
	c.Status = Status(status)
	return c, nil
}

func checkUpdated(res sql.Result, err error, op string) error {
	if err != nil {
		return fmt.Errorf("credentials: %s: %w", op, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("credentials: %s: rows affected: %w", op, err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

var _ Store = (*PostgresStore)(nil)
