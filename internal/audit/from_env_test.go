package audit

import (
	"context"
	"testing"
)

func TestFromEnv_NoDatabaseURL_ReturnsInMemorySink(t *testing.T) {
	t.Setenv(envDatabaseURL, "")
	s, err := FromEnv(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := s.(*InMemorySink); !ok {
		t.Fatalf("expected an *InMemorySink when %s is unset, got %T", envDatabaseURL, s)
	}
}

func TestFromEnv_DatabaseURLSetButUnreachable_IsAnErrorNotASilentFallback(t *testing.T) {
	// A set-but-bad DSN must fail loudly at startup, the same fail-fast
	// choice policy.FromEnv makes for a missing signing key, rather than
	// quietly falling back to an in-memory sink that would silently
	// stop sharing events with whatever else is pointed at the real
	// database.
	t.Setenv(envDatabaseURL, "postgres://nia:nia@127.0.0.1:1/nia?sslmode=disable&connect_timeout=1")
	if _, err := FromEnv(context.Background()); err == nil {
		t.Fatal("expected an error for an unreachable database, got nil")
	}
}

func TestFromEnv_DatabaseURLWithIncidentalWhitespace_StillUsed(t *testing.T) {
	// Same trim-before-check discipline as policy.FromEnv: a value with
	// leading or trailing whitespace from a sloppy .env parser must not
	// be treated as unset and silently swapped for the in-memory sink.
	t.Setenv(envDatabaseURL, "  postgres://nia:nia@127.0.0.1:1/nia?sslmode=disable&connect_timeout=1  ")
	_, err := FromEnv(context.Background())
	if err == nil {
		t.Fatal("expected an error dialing the unreachable address, got nil, which would mean the whitespace made this look unset")
	}
}
