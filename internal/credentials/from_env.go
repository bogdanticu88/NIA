package credentials

import (
	"context"
	"fmt"
	"os"
	"strings"
)

// envDatabaseURL is the one environment variable this package reads.
// Unset means InMemoryStore, the same "runs out of the box" default
// every FromEnv in this codebase uses. Set it to a standard postgres://
// DSN and every process started with the same value shares one
// credential store instead of each keeping its own private map, the
// whole reason PostgresStore exists: cmd/api issues a credential,
// cmd/gateway needs to Verify it, and a kill or revoke from either
// process needs to be visible to the other immediately, not
// eventually. A separate env var from NIA_AUDIT_DATABASE_URL on
// purpose, a deployment can point both at the same Postgres instance
// (deployments/docker-compose.yml does) or keep them apart, this
// package doesn't assume which.
const envDatabaseURL = "NIA_CREDENTIALS_DATABASE_URL"

// FromEnv builds the Store cmd/api and cmd/gateway actually run
// against. Takes a context for the same reason audit.FromEnv does:
// standing up a Postgres-backed store means a real connection and a
// schema check before this can return, better to fail at startup than
// on the first Verify call nobody's watching for.
func FromEnv(ctx context.Context) (Store, error) {
	dsn := strings.TrimSpace(os.Getenv(envDatabaseURL))
	if dsn == "" {
		return NewInMemoryStore(), nil
	}
	store, err := NewPostgresStore(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("credentials: %w", err)
	}
	return store, nil
}
