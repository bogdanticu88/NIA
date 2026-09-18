// Package dbschema runs each store's CREATE TABLE IF NOT EXISTS
// bootstrap so that several NIA processes starting at the same moment
// bootstrap the schema once between them instead of racing.
//
// The problem it solves is not theoretical. Postgres's IF NOT EXISTS
// is a check, not a lock: two backends that both find the table absent
// both go on to create it, and one of them loses on the catalog's own
// unique index. Three replicas started together against an empty
// database reproducibly failed two out of three times with
//
//	pq: duplicate key value violates unique constraint "pg_class_relname_nsp_index"
//	pq: duplicate key value violates unique constraint "pg_type_typname_nsp_index"
//	pq: relation "audit_events" already exists
//	pq: deadlock detected
//
// and since every store treats a failed bootstrap as fatal at
// construction, those replicas did not start at all. A control plane
// documented as safe to run behind a load balancer has to survive its
// own cold start, so this is a correctness fix rather than a tidying
// one.
//
// Retrying the DDL on those errors would also work and is what a lot of
// code does. A lock is preferable here because it is the same answer
// for all of them, including the deadlock, and because it leaves no
// window where a replica is running against a half-created schema.
package dbschema

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// schemaLockClass namespaces these locks inside Postgres's advisory
// lock space, which is global to the database. It is deliberately not
// internal/policy's class id: two unrelated pieces of code sharing a
// namespace can block each other for no reason, and the grant lock is
// held across HTTP calls to Tessera, which is exactly the thing a
// startup path should not be waiting behind.
//
// The value is arbitrary but must never change, because it is part of
// the protocol between replicas: two versions of NIA using different
// class ids would not lock against each other while both believed they
// were serialized.
const schemaLockClass = 0x4E4953 // "NIS", NIA schema

// schemaLockID is one lock for all schema bootstrapping rather than one
// per store. Bootstrapping happens once per process at startup and
// takes milliseconds, so there is nothing to gain from letting two
// stores create their tables concurrently, and a single lock is one
// less thing to reason about.
const schemaLockID = 1

// lockTimeout bounds the wait. A process that cannot get the lock
// inside this window is better off failing to start with a clear error
// than hanging forever behind something stuck, which is the same
// fail-fast-at-startup choice every store's constructor already makes.
const lockTimeout = 30 * time.Second

// Apply executes statements in order, all of them under the advisory
// lock, on one connection.
//
// One connection matters: pg_advisory_lock is session scoped, so the
// lock and the DDL it protects have to run on the same session. Taking
// it from the pool and handing the statements to the pool would be a
// lock that protects nothing.
//
// what names the caller for error messages, for example "audit" or
// "credentials", so a failure says which store could not be created.
func Apply(ctx context.Context, db *sql.DB, what string, statements ...string) error {
	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("%s: acquiring a connection for the schema lock: %w", what, err)
	}
	defer conn.Close()

	// pg_advisory_lock has no timeout argument of its own, so the
	// session's lock_timeout is what turns "wait forever" into an error.
	if _, err := conn.ExecContext(ctx, fmt.Sprintf(`SET lock_timeout = %d`, lockTimeout.Milliseconds())); err != nil {
		return fmt.Errorf("%s: setting the schema lock timeout: %w", what, err)
	}
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock($1, $2)`, schemaLockClass, schemaLockID); err != nil {
		return fmt.Errorf("%s: waiting for the schema lock: %w", what, err)
	}
	defer func() {
		// Released on a background context on purpose: if the caller's
		// context was cancelled mid-bootstrap the lock still has to come
		// off, and a cancelled context would leave it held until the
		// connection dropped. Closing the connection releases it anyway,
		// so an error here is a diagnostic rather than a leak.
		_, _ = conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock($1, $2)`, schemaLockClass, schemaLockID)
	}()

	for _, statement := range statements {
		if _, err := conn.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("%s: creating schema: %w", what, err)
		}
	}
	return nil
}
