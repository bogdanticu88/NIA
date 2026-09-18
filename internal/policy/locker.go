package policy

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "github.com/lib/pq"
)

// Locker serializes an operation across processes, not just within one.
//
// TesseraHTTPClient's WriteGrants and DeleteGrants are read, merge, then
// full onboard, because Tessera's surface has no incremental grant
// endpoint. That is a read-modify-write over HTTP, and it has the
// problem every read-modify-write has: something else can change the
// record between the read and the write, and the second writer's merge
// was computed against a state that no longer exists. Concretely, two
// replicas adding a different grant to the same agent at the same time
// can leave only one of the two grants written, with no error on either
// side.
//
// The per-agentRef mutex in TesseraHTTPClient covers exactly one client
// instance, which is one replica, and the client's own doc comment has
// said so from the start. This is the shared lock that comment said was
// needed and not implemented.
//
// Lock returns a release function that must be called, and only that
// function releases the lock, so a caller defers it the way it defers a
// mutex unlock.
type Locker interface {
	Lock(ctx context.Context, key string) (release func(), err error)
}

// NoopLocker is the default: no cross-process serialization at all,
// which is the behaviour every deployment had before this existed and
// the right one for a single replica, where the in-process mutex is
// already sufficient. Named rather than expressed as a nil Locker so a
// caller reading the wiring sees the choice being made.
type NoopLocker struct{}

func (NoopLocker) Lock(context.Context, string) (func(), error) { return func() {}, nil }

// policyLockClass namespaces these locks inside Postgres's advisory lock
// space. Advisory locks are global to the database, so two unrelated
// pieces of code hashing different strings into the same number would
// block each other for no reason and, worse, could deadlock. The
// two-argument form (classid, objid) is a different lock space from the
// single-argument form, which is what internal/risk's call history uses,
// so those two cannot collide even by accident.
//
// The value is arbitrary but must never change: it is part of the
// protocol between replicas, and two versions of NIA using different
// class ids would not lock against each other while both believing they
// were serialized.
const policyLockClass = 0x4E49 // "NI"

// PostgresLocker implements Locker with Postgres advisory locks.
//
// Session-scoped (pg_advisory_lock) on a dedicated connection rather
// than transaction-scoped, because the critical section here is several
// HTTP calls to Tessera, not a database transaction, and holding an
// open transaction across a network round trip to a third service is a
// good way to tie up a connection for as long as that service is slow.
type PostgresLocker struct {
	db *sql.DB
	// timeout bounds how long Lock waits before giving up. Without it a
	// replica that hangs mid-onboard would block every other replica's
	// grant writes for that agent indefinitely, turning one stuck
	// process into an outage.
	timeout time.Duration
}

// NewPostgresLocker opens a pool against dsn and confirms it works.
func NewPostgresLocker(ctx context.Context, dsn string) (*PostgresLocker, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("policy: opening postgres for the grant lock: %w", err)
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("policy: postgres unreachable for the grant lock: %w", err)
	}
	// Small pool: one connection is held for the duration of each held
	// lock, and grant writes are an operator-paced control-plane
	// operation, not hot path.
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(30 * time.Minute)
	return &PostgresLocker{db: db, timeout: 15 * time.Second}, nil
}

func (l *PostgresLocker) Close() error { return l.db.Close() }

func (l *PostgresLocker) Lock(ctx context.Context, key string) (func(), error) {
	conn, err := l.db.Conn(ctx)
	if err != nil {
		return nil, fmt.Errorf("policy: acquiring a connection for the grant lock on %s: %w", key, err)
	}

	// lock_timeout turns "wait forever" into a real error. Set on the
	// session rather than passed per statement because pg_advisory_lock
	// has no timeout argument of its own.
	if _, err := conn.ExecContext(ctx, fmt.Sprintf(`SET lock_timeout = %d`, l.timeout.Milliseconds())); err != nil {
		conn.Close()
		return nil, fmt.Errorf("policy: setting the grant lock timeout for %s: %w", key, err)
	}
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock($1, hashtext($2))`, policyLockClass, key); err != nil {
		conn.Close()
		return nil, fmt.Errorf("policy: waiting for the grant lock on %s: %w", key, err)
	}

	return func() {
		// Released on a background context on purpose: if the caller's
		// context was cancelled mid-operation, the lock still has to come
		// off, and using the cancelled context would leave it held until
		// the connection dropped.
		if _, err := conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock($1, hashtext($2))`, policyLockClass, key); err != nil {
			// Closing the connection releases a session-scoped advisory
			// lock regardless, so this is a diagnostic rather than a leak.
			_ = err
		}
		conn.Close()
	}, nil
}

// envLockDatabaseURL configures the shared grant lock. Unset means
// NoopLocker and the previous behaviour, which is correct for a single
// replica: the in-process mutex already serializes everything that one
// process does. Set it, to any Postgres the replicas share, and grant
// writes for the same agent are serialized across all of them.
//
// Deliberately its own variable rather than reusing one of the store
// DSNs. They happen to point at the same database in this repo's own
// compose file, but "which database holds the audit trail" and "where
// do replicas coordinate" are different questions, and a deployment
// that splits them should be able to.
const envLockDatabaseURL = "NIA_POLICY_LOCK_DATABASE_URL"

// LockerFromEnv builds the Locker the policy client should use and
// reports whether it is the shared one, so a caller can log which it
// got rather than leaving an operator to guess.
func LockerFromEnv(ctx context.Context, getenv func(string) string) (Locker, bool, error) {
	dsn := strings.TrimSpace(getenv(envLockDatabaseURL))
	if dsn == "" {
		return NoopLocker{}, false, nil
	}
	l, err := NewPostgresLocker(ctx, dsn)
	if err != nil {
		return nil, false, err
	}
	return l, true, nil
}
