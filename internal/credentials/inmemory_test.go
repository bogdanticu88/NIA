package credentials

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestInMemoryStore_IssueAndGet(t *testing.T) {
	s := NewInMemoryStore()
	ctx := context.Background()

	cred, err := s.Issue(ctx, "agent:billing", KindAPIKey, 0)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if cred.ID == "" {
		t.Fatalf("Issue returned a credential with no ID")
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

	cred, err := s.Issue(context.Background(), "agent:billing", KindOAuthToken, time.Hour)
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

	if _, err := s.Issue(ctx, "agent:billing", KindAPIKey, 0); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := s.Issue(ctx, "agent:billing", KindMTLSCert, 0); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := s.Issue(ctx, "agent:reporting", KindAPIKey, 0); err != nil {
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

	cred, err := s.Issue(ctx, "agent:billing", KindAPIKey, 0)
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

	cred, err := s.Issue(ctx, "agent:billing", KindAPIKey, 0)
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

var _ Store = (*InMemoryStore)(nil)
