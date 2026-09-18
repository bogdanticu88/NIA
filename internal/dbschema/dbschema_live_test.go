package dbschema

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

// probeSchemaSQL is deliberately the same shape as a real store's
// bootstrap, a table with a BIGSERIAL primary key, two indexes and two
// added columns, because that shape is what makes the race reachable:
// each of those statements touches a different catalog with its own
// unique index, and the sequence and index that BIGSERIAL implies are
// two more relations to collide on.
const probeSchemaSQL = `
CREATE TABLE IF NOT EXISTS dbschema_probe (
	id        BIGSERIAL PRIMARY KEY,
	action    TEXT NOT NULL,
	agent_ref TEXT NOT NULL DEFAULT '',
	at        TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS dbschema_probe_agent_ref_idx ON dbschema_probe (agent_ref, at);
CREATE INDEX IF NOT EXISTS dbschema_probe_at_idx ON dbschema_probe (at);
ALTER TABLE dbschema_probe ADD COLUMN IF NOT EXISTS hash TEXT NOT NULL DEFAULT '';
`

// TestApply_ConcurrentBootstrap_Live is the regression test for replica
// cold start. Eight processes starting against an empty database is
// what a scaled deployment does on its first rollout, and before Apply
// took a lock, running the same DDL from eight connections at once
// failed seven times out of eight against a real Postgres with
// "duplicate key value violates unique constraint
// pg_class_relname_nsp_index", "relation already exists" and
// "deadlock detected". Every one of those aborted a replica at
// construction, because every store treats a failed bootstrap as fatal.
//
// Opt-in via NIA_DBSCHEMA_TEST_DATABASE_URL, skipped by default, same
// pattern as the other live Postgres tests in this repo. This one has
// to be live: the failure is in Postgres's catalog, an in-memory stand
// in cannot have it.
func TestApply_ConcurrentBootstrap_Live(t *testing.T) {
	dsn := os.Getenv("NIA_DBSCHEMA_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NIA_DBSCHEMA_TEST_DATABASE_URL not set, skipping live Postgres test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// A genuinely empty starting point, because the race only exists on
	// the first bootstrap. Running this against a database where the
	// table already exists would pass without proving anything.
	cleanup, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("opening postgres: %v", err)
	}
	defer cleanup.Close()
	if _, err := cleanup.ExecContext(ctx, `DROP TABLE IF EXISTS dbschema_probe`); err != nil {
		t.Fatalf("dropping the probe table: %v", err)
	}
	t.Cleanup(func() {
		_, _ = cleanup.ExecContext(context.Background(), `DROP TABLE IF EXISTS dbschema_probe`)
	})

	// Separate pools rather than one shared pool, so this is as close as
	// a single test process gets to separate replicas: nothing is shared
	// between them except the database itself.
	const replicas = 8
	errs := make([]error, replicas)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < replicas; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			db, err := sql.Open("postgres", dsn)
			if err != nil {
				errs[i] = err
				return
			}
			defer db.Close()
			<-start
			errs[i] = Apply(ctx, db, fmt.Sprintf("replica-%d", i), probeSchemaSQL)
		}(i)
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("replica %d failed to bootstrap the schema: %v", i, err)
		}
	}

	// Bootstrapped once, not eight times: a lock that serialized the DDL
	// but let each holder recreate the table would pass the check above
	// and still be wrong.
	var indexes int
	if err := cleanup.QueryRowContext(ctx,
		`SELECT count(*) FROM pg_indexes WHERE tablename = 'dbschema_probe'`,
	).Scan(&indexes); err != nil {
		t.Fatalf("counting the probe table's indexes: %v", err)
	}
	if indexes != 3 {
		t.Errorf("probe table has %d indexes, want 3 (the primary key and the two named ones)", indexes)
	}
}

// TestApply_RepeatBootstrap_Live is the other half: Apply has to be
// safe to run again on every process start, which is exactly what
// happens each time a replica restarts against a database that already
// has its schema.
func TestApply_RepeatBootstrap_Live(t *testing.T) {
	dsn := os.Getenv("NIA_DBSCHEMA_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NIA_DBSCHEMA_TEST_DATABASE_URL not set, skipping live Postgres test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("opening postgres: %v", err)
	}
	defer db.Close()
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DROP TABLE IF EXISTS dbschema_probe`)
	})

	for i := 0; i < 3; i++ {
		if err := Apply(ctx, db, "repeat", probeSchemaSQL); err != nil {
			t.Fatalf("bootstrap %d: %v", i+1, err)
		}
	}
}

// TestApply_ReleasesTheLock_Live guards against the failure that would
// be invisible in the tests above: a lock that is taken and never
// released still lets one caller through, so everything looks fine
// until the second process starts and hangs for lockTimeout.
//
// It proves the release by taking the lock again from a separate
// connection under a short lock_timeout, rather than by counting rows
// in pg_locks. Counting would be the obvious check and would be flaky:
// every store's bootstrap shares this lock now, so a live test in
// another package running at the same time can legitimately be holding
// it for the millisecond this one looks. Re-acquiring tolerates that,
// it just waits, and only fails if the lock is genuinely stuck.
func TestApply_ReleasesTheLock_Live(t *testing.T) {
	dsn := os.Getenv("NIA_DBSCHEMA_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NIA_DBSCHEMA_TEST_DATABASE_URL not set, skipping live Postgres test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("opening postgres: %v", err)
	}
	defer db.Close()
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DROP TABLE IF EXISTS dbschema_probe`)
	})

	if err := Apply(ctx, db, "holder", probeSchemaSQL); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatalf("acquiring a connection: %v", err)
	}
	defer conn.Close()
	// Generous against a bootstrap that takes milliseconds, short enough
	// that a lock Apply forgot to release fails the test rather than
	// stalling it for the real lockTimeout.
	if _, err := conn.ExecContext(ctx, `SET lock_timeout = 2000`); err != nil {
		t.Fatalf("setting lock_timeout: %v", err)
	}
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock($1, $2)`, schemaLockClass, schemaLockID); err != nil {
		t.Fatalf("the schema lock was still held after Apply returned: %v", err)
	}
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_unlock($1, $2)`, schemaLockClass, schemaLockID); err != nil {
		t.Fatalf("releasing the lock this test took: %v", err)
	}
}
