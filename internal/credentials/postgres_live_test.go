package credentials

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

// TestPostgresStore_Live drives a real Postgres instance end to end:
// schema creation on first connect, issue, verify, revoke, disable,
// enable, and rotate, against actual SQL, not the in-memory reference.
// Opt-in via NIA_CREDENTIALS_TEST_DATABASE_URL (a standard postgres://
// DSN), skipped by default, same pattern
// internal/audit/postgres_sink_live_test.go uses.
// deployments/docker-compose.yml's postgres service, once up, is
// reachable from the host at
// postgres://nia:nia@localhost:5433/nia?sslmode=disable.
func TestPostgresStore_Live(t *testing.T) {
	dsn := os.Getenv("NIA_CREDENTIALS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NIA_CREDENTIALS_TEST_DATABASE_URL not set, skipping live Postgres test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	store, err := NewPostgresStore(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	agentRef := "agent:live-test-" + time.Now().Format("20060102T150405.000000000")

	cred, secret, err := store.Issue(ctx, agentRef, KindAPIKey, 0)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if secret == "" {
		t.Fatalf("Issue returned an empty secret")
	}

	got, err := store.Verify(ctx, cred.ID, secret)
	if err != nil {
		t.Fatalf("Verify a freshly issued credential: %v", err)
	}
	if got.AgentRef != agentRef {
		t.Fatalf("Verify returned AgentRef %q, want %q", got.AgentRef, agentRef)
	}

	if _, err := store.Verify(ctx, cred.ID, "wrong-secret"); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("Verify with wrong secret: got %v, want ErrInvalidCredential", err)
	}

	// Rotate against a real transaction: the old secret must stop
	// working and the new one must work, both against actual committed
	// Postgres state, not an in-process map.
	next, nextSecret, err := store.Rotate(ctx, cred.ID, "bogdan", 0)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if _, err := store.Verify(ctx, cred.ID, secret); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("Verify with the old credential after Rotate: got %v, want ErrInvalidCredential", err)
	}
	if _, err := store.Verify(ctx, next.ID, nextSecret); err != nil {
		t.Fatalf("Verify with the rotated-to credential: %v", err)
	}
	oldRow, err := store.Get(ctx, cred.ID)
	if err != nil {
		t.Fatalf("Get on the rotated-away credential: %v", err)
	}
	if oldRow.Status != StatusRevoked || oldRow.RotatedTo != next.ID {
		t.Fatalf("old credential after Rotate = %+v, want Revoked with RotatedTo=%s", oldRow, next.ID)
	}

	// Disable, then Enable, against real rows.
	if err := store.Disable(ctx, next.ID, "bogdan", "paused for maintenance"); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	if _, err := store.Verify(ctx, next.ID, nextSecret); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("Verify a disabled credential: got %v, want ErrInvalidCredential", err)
	}
	if err := store.Enable(ctx, next.ID, "bogdan"); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	if _, err := store.Verify(ctx, next.ID, nextSecret); err != nil {
		t.Fatalf("Verify after re-enabling: %v", err)
	}

	// Revoke is terminal, Enable afterward must be refused.
	if err := store.Revoke(ctx, next.ID, "bogdan", "incident cleanup"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := store.Verify(ctx, next.ID, nextSecret); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("Verify a revoked credential: got %v, want ErrInvalidCredential", err)
	}
	if err := store.Enable(ctx, next.ID, "bogdan"); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("Enable on a revoked credential: got %v, want ErrInvalidCredential", err)
	}

	list, err := store.ListForAgent(ctx, agentRef)
	if err != nil {
		t.Fatalf("ListForAgent: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("ListForAgent returned %d credentials for %s, want 2 (the original and the rotated-to one): %+v", len(list), agentRef, list)
	}
}
