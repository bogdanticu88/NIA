package audit

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
)

// CheckpointStore is where signed checkpoints are kept so a later
// verification has something to compare against.
//
// Keeping them in the same database as the events is worth being honest
// about: an attacker with write access there can delete them. What they
// cannot do is forge a new one, because the signing key is not in the
// database, so the attack degrades from "rewrite history into a
// different history that verifies" to "destroy the checkpoints," which
// is noisy and leaves the trail unanchored rather than convincingly
// wrong. An operator who wants more than that exports checkpoints and
// keeps them somewhere else, which is exactly why Latest and List are on
// the HTTP surface.
type CheckpointStore interface {
	Save(ctx context.Context, cp Checkpoint) error
	Latest(ctx context.Context) (Checkpoint, error)
	List(ctx context.Context, limit int) ([]Checkpoint, error)
}

// ErrNoCheckpoints is returned by Latest when none has ever been saved.
var ErrNoCheckpoints = errors.New("audit: no checkpoint has been saved")

// InMemoryCheckpointStore is the reference implementation, used when no
// database is configured. Checkpoints in memory die with the process,
// which makes them nearly useless as an anchor, so this exists to keep
// the code paths exercised rather than to be relied on.
type InMemoryCheckpointStore struct {
	mu          sync.Mutex
	checkpoints []Checkpoint
}

func NewInMemoryCheckpointStore() *InMemoryCheckpointStore {
	return &InMemoryCheckpointStore{}
}

func (s *InMemoryCheckpointStore) Save(_ context.Context, cp Checkpoint) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.checkpoints = append(s.checkpoints, cp)
	return nil
}

func (s *InMemoryCheckpointStore) Latest(_ context.Context) (Checkpoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.checkpoints) == 0 {
		return Checkpoint{}, ErrNoCheckpoints
	}
	return s.checkpoints[len(s.checkpoints)-1], nil
}

func (s *InMemoryCheckpointStore) List(_ context.Context, limit int) ([]Checkpoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Checkpoint, len(s.checkpoints))
	copy(out, s.checkpoints)
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out, nil
}

const checkpointSchemaSQL = `
CREATE TABLE IF NOT EXISTS audit_checkpoints (
	seq        BIGINT NOT NULL,
	hash       TEXT NOT NULL,
	created_at TIMESTAMPTZ NOT NULL,
	signature  TEXT NOT NULL,
	PRIMARY KEY (created_at, seq)
);
`

// PostgresCheckpointStore keeps checkpoints in the audit database.
type PostgresCheckpointStore struct {
	db *sql.DB
}

func NewPostgresCheckpointStore(ctx context.Context, dsn string) (*PostgresCheckpointStore, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("audit: opening postgres for checkpoints: %w", err)
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("audit: postgres unreachable for checkpoints: %w", err)
	}
	if _, err := db.ExecContext(ctx, checkpointSchemaSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("audit: creating audit_checkpoints schema: %w", err)
	}
	db.SetMaxOpenConns(maxOpenConns)
	db.SetMaxIdleConns(maxIdleConns)
	db.SetConnMaxLifetime(connMaxLifetime)
	return &PostgresCheckpointStore{db: db}, nil
}

func (s *PostgresCheckpointStore) Close() error { return s.db.Close() }

func (s *PostgresCheckpointStore) Save(ctx context.Context, cp Checkpoint) error {
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO audit_checkpoints (seq, hash, created_at, signature) VALUES ($1, $2, $3, $4)`,
		cp.Seq, cp.Hash, cp.CreatedAt, cp.Signature,
	); err != nil {
		return fmt.Errorf("audit: saving checkpoint: %w", err)
	}
	return nil
}

func (s *PostgresCheckpointStore) Latest(ctx context.Context) (Checkpoint, error) {
	var cp Checkpoint
	err := s.db.QueryRowContext(ctx,
		`SELECT seq, hash, created_at, signature FROM audit_checkpoints ORDER BY created_at DESC, seq DESC LIMIT 1`,
	).Scan(&cp.Seq, &cp.Hash, &cp.CreatedAt, &cp.Signature)
	if errors.Is(err, sql.ErrNoRows) {
		return Checkpoint{}, ErrNoCheckpoints
	}
	if err != nil {
		return Checkpoint{}, fmt.Errorf("audit: reading the latest checkpoint: %w", err)
	}
	return cp, nil
}

func (s *PostgresCheckpointStore) List(ctx context.Context, limit int) ([]Checkpoint, error) {
	query := `SELECT seq, hash, created_at, signature FROM audit_checkpoints ORDER BY created_at DESC, seq DESC`
	args := []any{}
	if limit > 0 {
		query += ` LIMIT $1`
		args = append(args, limit)
	}
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("audit: listing checkpoints: %w", err)
	}
	defer rows.Close()

	out := make([]Checkpoint, 0)
	for rows.Next() {
		var cp Checkpoint
		if err := rows.Scan(&cp.Seq, &cp.Hash, &cp.CreatedAt, &cp.Signature); err != nil {
			return nil, fmt.Errorf("audit: listing checkpoints: %w", err)
		}
		out = append(out, cp)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit: listing checkpoints: %w", err)
	}
	return out, nil
}

// envCheckpointKey holds the base64 HMAC key checkpoints are signed
// with. Unset means checkpointing is off and the audit trail is
// tamper-evident but unanchored, which is where it was before this
// existed.
//
// The key must not live in the audit database. That is the entire
// mechanism: an attacker who can rewrite audit_events still cannot
// produce a checkpoint that verifies for the rewritten history, and
// that only holds while the key is somewhere they do not have.
const envCheckpointKey = "NIA_AUDIT_CHECKPOINT_KEY"

// CheckpointerFromEnv builds the Checkpointer this process should use.
// Returns a nil Checkpointer and no error when unset, which every method
// handles as ErrNoCheckpointKey, so a caller can hold it unconditionally.
func CheckpointerFromEnv() (*Checkpointer, error) {
	raw := strings.TrimSpace(os.Getenv(envCheckpointKey))
	if raw == "" {
		return nil, nil
	}
	key, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("audit: %s is not valid base64: %w", envCheckpointKey, err)
	}
	return NewCheckpointer(key)
}

// CheckpointStoreFromEnv reuses the audit database when one is
// configured, because a checkpoint with nowhere durable to live is not
// an anchor. Reports whether the store is the durable one.
func CheckpointStoreFromEnv(ctx context.Context) (CheckpointStore, bool, error) {
	dsn := strings.TrimSpace(os.Getenv(envDatabaseURL))
	if dsn == "" {
		return NewInMemoryCheckpointStore(), false, nil
	}
	s, err := NewPostgresCheckpointStore(ctx, dsn)
	if err != nil {
		return nil, false, err
	}
	return s, true, nil
}

// checkpointRetention is what List returns by default, enough for an
// operator to see the recent anchors without paging through years of
// them.
const checkpointRetention = 50
