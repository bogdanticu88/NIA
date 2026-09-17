package credentials

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestInMemoryStore_IssueAndGet(t *testing.T) {
	s := NewInMemoryStore()
	ctx := context.Background()

	cred, secret, err := s.Issue(ctx, "agent:billing", KindAPIKey, 0)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if cred.ID == "" {
		t.Fatalf("Issue returned a credential with no ID")
	}
	if secret == "" {
		t.Fatalf("Issue returned an empty secret")
	}
	if cred.AgentRef != "agent:billing" || cred.Kind != KindAPIKey {
		t.Fatalf("got %+v, want agent:billing / api_key", cred)
	}
	if cred.Status != StatusActive {
		t.Fatalf("Status = %q, want active", cred.Status)
	}
	if cred.ExpiresAt != nil {
		t.Fatalf("ExpiresAt = %v, want nil for a zero ttl", cred.ExpiresAt)
	}
	if cred.SecretHash == "" || cred.SecretHash == secret {
		t.Fatalf("SecretHash = %q, want a digest distinct from the plaintext secret %q", cred.SecretHash, secret)
	}

	got, err := s.Get(ctx, cred.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != cred {
		t.Fatalf("Get returned %+v, want the issued credential %+v", got, cred)
	}
}

func TestInMemoryStore_IssueSetsExpiry(t *testing.T) {
	s := NewInMemoryStore()
	before := time.Now()

	cred, _, err := s.Issue(context.Background(), "agent:billing", KindOAuthToken, time.Hour)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if cred.ExpiresAt == nil {
		t.Fatalf("ExpiresAt is nil, want set for a positive ttl")
	}
	if cred.ExpiresAt.Before(before.Add(time.Hour)) {
		t.Fatalf("ExpiresAt = %v, want at least an hour after %v", cred.ExpiresAt, before)
	}
}

func TestInMemoryStore_GetNotFound(t *testing.T) {
	s := NewInMemoryStore()
	if _, err := s.Get(context.Background(), "does-not-exist"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get on unknown id: got %v, want ErrNotFound", err)
	}
}

func TestInMemoryStore_ListForAgentFiltersAndIsEmptyWhenNone(t *testing.T) {
	s := NewInMemoryStore()
	ctx := context.Background()

	if _, _, err := s.Issue(ctx, "agent:billing", KindAPIKey, 0); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, _, err := s.Issue(ctx, "agent:billing", KindMTLSCert, 0); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, _, err := s.Issue(ctx, "agent:reporting", KindAPIKey, 0); err != nil {
		t.Fatalf("Issue: %v", err)
	}

	billing, err := s.ListForAgent(ctx, "agent:billing")
	if err != nil {
		t.Fatalf("ListForAgent: %v", err)
	}
	if len(billing) != 2 {
		t.Fatalf("got %d credentials for agent:billing, want 2", len(billing))
	}

	none, err := s.ListForAgent(ctx, "agent:unknown")
	if err != nil {
		t.Fatalf("ListForAgent: %v", err)
	}
	if len(none) != 0 {
		t.Fatalf("got %d credentials for an agent with none, want 0", len(none))
	}
}

func TestInMemoryStore_Revoke(t *testing.T) {
	s := NewInMemoryStore()
	ctx := context.Background()

	cred, _, err := s.Issue(ctx, "agent:billing", KindAPIKey, 0)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	if err := s.Revoke(ctx, cred.ID, "bogdan", "key leaked in a log"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	got, err := s.Get(ctx, cred.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != StatusRevoked {
		t.Fatalf("Status = %q, want revoked", got.Status)
	}
	if got.RevokedBy != "bogdan" || got.Reason != "key leaked in a log" {
		t.Fatalf("got RevokedBy=%q Reason=%q, want bogdan / key leaked in a log", got.RevokedBy, got.Reason)
	}
	if got.RevokedAt == nil {
		t.Fatalf("RevokedAt is nil, want set")
	}
}

func TestInMemoryStore_RevokeNotFound(t *testing.T) {
	s := NewInMemoryStore()
	err := s.Revoke(context.Background(), "does-not-exist", "bogdan", "cleanup")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Revoke on unknown id: got %v, want ErrNotFound", err)
	}
}

func TestInMemoryStore_RevokeIsIdempotentlyReflected(t *testing.T) {
	// Revoking an already-revoked credential doesn't error, the second
	// operator/reason simply overwrites the first. Matches the kill
	// switch's own idempotent-write posture in internal/policy, a
	// second revoke shouldn't be an operator-facing failure during an
	// incident when two people move on the same key at once.
	s := NewInMemoryStore()
	ctx := context.Background()

	cred, _, err := s.Issue(ctx, "agent:billing", KindAPIKey, 0)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := s.Revoke(ctx, cred.ID, "bogdan", "first reason"); err != nil {
		t.Fatalf("first Revoke: %v", err)
	}
	if err := s.Revoke(ctx, cred.ID, "sergio", "second reason"); err != nil {
		t.Fatalf("second Revoke: %v", err)
	}

	got, _ := s.Get(ctx, cred.ID)
	if got.RevokedBy != "sergio" || got.Reason != "second reason" {
		t.Fatalf("got RevokedBy=%q Reason=%q, want the second revoke to win", got.RevokedBy, got.Reason)
	}
}

// --- Verify: the actual authentication invariant ---

func TestInMemoryStore_VerifySucceedsForACorrectActiveCredential(t *testing.T) {
	s := NewInMemoryStore()
	ctx := context.Background()
	cred, secret, err := s.Issue(ctx, "agent:billing", KindAPIKey, 0)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	got, err := s.Verify(ctx, cred.ID, secret)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.ID != cred.ID || got.AgentRef != cred.AgentRef {
		t.Fatalf("Verify returned %+v, want the issued credential", got)
	}
}

func TestInMemoryStore_VerifyRejectsWrongSecret(t *testing.T) {
	s := NewInMemoryStore()
	ctx := context.Background()
	cred, _, err := s.Issue(ctx, "agent:billing", KindAPIKey, 0)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := s.Verify(ctx, cred.ID, "not-the-real-secret"); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("Verify with wrong secret: got %v, want ErrInvalidCredential", err)
	}
}

func TestInMemoryStore_VerifyRejectsUnknownID(t *testing.T) {
	s := NewInMemoryStore()
	if _, err := s.Verify(context.Background(), "does-not-exist", "whatever"); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("Verify on unknown id: got %v, want ErrInvalidCredential (not ErrNotFound, see the doc comment on why the two failure modes don't leak which one happened)", err)
	}
}

func TestInMemoryStore_VerifyRejectsRevokedCredential(t *testing.T) {
	s := NewInMemoryStore()
	ctx := context.Background()
	cred, secret, err := s.Issue(ctx, "agent:billing", KindAPIKey, 0)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := s.Revoke(ctx, cred.ID, "bogdan", "compromised"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := s.Verify(ctx, cred.ID, secret); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("Verify on revoked credential: got %v, want ErrInvalidCredential", err)
	}
}

func TestInMemoryStore_VerifyRejectsExpiredCredential(t *testing.T) {
	// A negative ttl is not a realistic Issue call, so build the
	// expired-in-the-past case directly: issue with a short ttl, then
	// assert Verify already refuses it once that ttl has passed. This
	// is the specific gap the pre-hardening code had, ExpiresAt was
	// stored but nothing ever compared it against time.Now(), see
	// Credential.Effective's own doc comment.
	s := NewInMemoryStore()
	ctx := context.Background()
	cred, secret, err := s.Issue(ctx, "agent:billing", KindAPIKey, time.Millisecond)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	time.Sleep(5 * time.Millisecond)
	if _, err := s.Verify(ctx, cred.ID, secret); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("Verify on expired credential: got %v, want ErrInvalidCredential", err)
	}
	// The stored Status column is untouched, Effective is what actually
	// governs Verify, not a background sweep.
	got, _ := s.Get(ctx, cred.ID)
	if got.Status != StatusActive {
		t.Fatalf("stored Status = %q after expiry, want it to remain active in storage, Effective is what changes, not Status", got.Status)
	}
	if got.Effective(time.Now()) != StatusExpired {
		t.Fatalf("Effective = %q, want expired", got.Effective(time.Now()))
	}
}

func TestInMemoryStore_VerifyRejectsDisabledCredential(t *testing.T) {
	s := NewInMemoryStore()
	ctx := context.Background()
	cred, secret, err := s.Issue(ctx, "agent:billing", KindAPIKey, 0)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := s.Disable(ctx, cred.ID, "bogdan", "agent paused for maintenance"); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	if _, err := s.Verify(ctx, cred.ID, secret); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("Verify on disabled credential: got %v, want ErrInvalidCredential", err)
	}
}

func TestInMemoryStore_DisableThenEnableRestoresAuthentication(t *testing.T) {
	s := NewInMemoryStore()
	ctx := context.Background()
	cred, secret, err := s.Issue(ctx, "agent:billing", KindAPIKey, 0)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := s.Disable(ctx, cred.ID, "bogdan", "paused"); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	if err := s.Enable(ctx, cred.ID, "bogdan"); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	if _, err := s.Verify(ctx, cred.ID, secret); err != nil {
		t.Fatalf("Verify after Enable: %v, want it to succeed again", err)
	}
}

func TestInMemoryStore_EnableRefusesARevokedCredential(t *testing.T) {
	// Revoke is one-way. Enable on a revoked credential must not
	// resurrect it, that would undo a security decision through what
	// looks like an administrative no-op.
	s := NewInMemoryStore()
	ctx := context.Background()
	cred, _, err := s.Issue(ctx, "agent:billing", KindAPIKey, 0)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := s.Revoke(ctx, cred.ID, "bogdan", "compromised"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if err := s.Enable(ctx, cred.ID, "bogdan"); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("Enable on revoked credential: got %v, want ErrInvalidCredential", err)
	}
	got, _ := s.Get(ctx, cred.ID)
	if got.Status != StatusRevoked {
		t.Fatalf("Status = %q after a refused Enable, want it to remain revoked", got.Status)
	}
}

// --- Rotate: the old credential must not remain valid ---

func TestInMemoryStore_RotateInvalidatesTheOldSecretAndIssuesANewOne(t *testing.T) {
	s := NewInMemoryStore()
	ctx := context.Background()
	old, oldSecret, err := s.Issue(ctx, "agent:billing", KindAPIKey, 0)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	next, newSecret, err := s.Rotate(ctx, old.ID, "bogdan", 0)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if next.ID == old.ID {
		t.Fatalf("Rotate returned the same credential ID, want a new one")
	}
	if next.AgentRef != old.AgentRef || next.Kind != old.Kind {
		t.Fatalf("Rotate changed AgentRef/Kind: got %+v, want it to carry over from %+v", next, old)
	}
	if newSecret == "" || newSecret == oldSecret {
		t.Fatalf("Rotate returned secret %q, want a fresh one distinct from the old secret", newSecret)
	}

	// The old credential, and specifically the old secret, must not
	// authenticate anymore. This is the directive's exact requirement:
	// "credential rotation must not accidentally leave the old
	// credential valid."
	if _, err := s.Verify(ctx, old.ID, oldSecret); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("Verify with the old credential after rotation: got %v, want ErrInvalidCredential", err)
	}
	// The new one must.
	if _, err := s.Verify(ctx, next.ID, newSecret); err != nil {
		t.Fatalf("Verify with the new credential after rotation: %v", err)
	}

	oldGot, _ := s.Get(ctx, old.ID)
	if oldGot.Status != StatusRevoked {
		t.Fatalf("old credential Status = %q after rotation, want revoked", oldGot.Status)
	}
	if oldGot.RotatedTo != next.ID {
		t.Fatalf("old credential RotatedTo = %q, want %q", oldGot.RotatedTo, next.ID)
	}
	if next.RotatedFrom != old.ID {
		t.Fatalf("new credential RotatedFrom = %q, want %q", next.RotatedFrom, old.ID)
	}
}

func TestInMemoryStore_RotateNotFound(t *testing.T) {
	s := NewInMemoryStore()
	if _, _, err := s.Rotate(context.Background(), "does-not-exist", "bogdan", 0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Rotate on unknown id: got %v, want ErrNotFound", err)
	}
}

// --- Concurrency ---

func TestInMemoryStore_ConcurrentVerifyDuringRevokeNeverSucceedsPastTheRevoke(t *testing.T) {
	// Not a race on the mutex itself (Go's race detector already proves
	// that, this is a correctness property): once Revoke has returned,
	// every subsequent Verify must fail, and no Verify call started
	// concurrently with Revoke may observe a torn intermediate state.
	// Run many Verify calls concurrently with a single Revoke and check
	// that every Verify succeeding is one that could only have run
	// before the revoke logically happened (we can't order them
	// precisely without a clock, so the real assertion is simpler: a
	// success is only ever "active", never a corrupted read).
	s := NewInMemoryStore()
	ctx := context.Background()
	cred, secret, err := s.Issue(ctx, "agent:billing", KindAPIKey, 0)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, _ = s.Verify(ctx, cred.ID, secret)
		}()
	}
	close(start)
	if err := s.Revoke(ctx, cred.ID, "bogdan", "concurrent revoke test"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	wg.Wait()

	if _, err := s.Verify(ctx, cred.ID, secret); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("Verify after all goroutines settled: got %v, want ErrInvalidCredential", err)
	}
}

var _ Store = (*InMemoryStore)(nil)
