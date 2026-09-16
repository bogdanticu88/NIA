package audit

import (
	"context"
	"fmt"
	"os"
	"strings"
)

// envDatabaseURL is the one environment variable this package reads.
// Unset means InMemorySink, the same "runs out of the box" default
// every other FromEnv in this codebase uses, see
// internal/policy/from_env.go. Set it to a standard postgres:// DSN and
// every process started with the same value shares one audit trail
// instead of each keeping its own, which is the whole reason this
// function exists, see PostgresSink's doc comment.
const envDatabaseURL = "NIA_AUDIT_DATABASE_URL"

// FromEnv builds the Store cmd/api and cmd/gateway actually run
// against. Takes a context, unlike policy.FromEnv, because standing up
// a Postgres-backed sink means opening a real connection and checking
// the schema before this can return successfully; better to fail at
// startup than on the first audit write nobody's watching for.
func FromEnv(ctx context.Context) (Store, error) {
	dsn := strings.TrimSpace(os.Getenv(envDatabaseURL))
	if dsn == "" {
		return NewInMemorySink(10_000), nil
	}
	sink, err := NewPostgresSink(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}
	return sink, nil
}
