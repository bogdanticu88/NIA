package opauth

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}

func newReloadingForTest(t *testing.T, content string) (*ReloadingStore, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tokens.json")
	writeFile(t, path, content)
	s, err := NewReloadingStore(path)
	if err != nil {
		t.Fatalf("NewReloadingStore: %v", err)
	}
	// Reload on every call, so tests assert behaviour rather than
	// waiting out the production interval.
	s.interval = 0
	return s, path
}

func TestReloadingStore_BadFileIsAStartupError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens.json")
	writeFile(t, path, `not json`)
	if _, err := NewReloadingStore(path); err == nil {
		t.Fatal("NewReloadingStore accepted a malformed file, a bad file should fail at startup rather than on the first request")
	}
}

// TestReloadingStore_RemovingATokenRevokesIt is the whole point: a
// leaked operator token used to require editing the file and restarting
// every process.
func TestReloadingStore_RemovingATokenRevokesIt(t *testing.T) {
	s, path := newReloadingForTest(t, `[
		{"token":"tok-keep","name":"keeper","roles":["viewer"]},
		{"token":"tok-leaked","name":"leaked","roles":["admin"]}
	]`)
	ctx := context.Background()

	if _, err := s.Verify(ctx, "tok-leaked"); err != nil {
		t.Fatalf("the leaked token does not verify to begin with: %v", err)
	}

	writeFile(t, path, `[{"token":"tok-keep","name":"keeper","roles":["viewer"]}]`)

	if _, err := s.Verify(ctx, "tok-leaked"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Verify(removed token) = %v, want ErrInvalidToken without a restart", err)
	}
	if _, err := s.Verify(ctx, "tok-keep"); err != nil {
		t.Fatalf("the surviving token stopped working after the reload: %v", err)
	}
}

func TestReloadingStore_AddingATokenTakesEffect(t *testing.T) {
	s, path := newReloadingForTest(t, `[{"token":"tok-a","name":"a","roles":["viewer"]}]`)
	ctx := context.Background()

	if _, err := s.Verify(ctx, "tok-b"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Verify(tok-b) = %v before it exists, want ErrInvalidToken", err)
	}
	writeFile(t, path, `[
		{"token":"tok-a","name":"a","roles":["viewer"]},
		{"token":"tok-b","name":"b","roles":["operator"]}
	]`)
	op, err := s.Verify(ctx, "tok-b")
	if err != nil {
		t.Fatalf("Verify(tok-b) after adding it: %v", err)
	}
	if !op.Can(PermWrite) {
		t.Fatalf("the reloaded operator has roles %v, want write", op.RoleNames())
	}
}

// TestReloadingStore_ABrokenEditKeepsTheLastGoodTokens is the failure
// mode that matters more than the feature: a half-saved file or a stray
// comma must not lock every operator out of the control plane at once.
func TestReloadingStore_ABrokenEditKeepsTheLastGoodTokens(t *testing.T) {
	s, path := newReloadingForTest(t, `[{"token":"tok-a","name":"a","roles":["admin"]}]`)
	ctx := context.Background()

	var reloadErr error
	s.onError = func(err error) { reloadErr = err }

	writeFile(t, path, `[{"token":"tok-a", BROKEN`)

	if _, err := s.Verify(ctx, "tok-a"); err != nil {
		t.Fatalf("a malformed reload dropped the previously loaded tokens: %v", err)
	}
	if reloadErr == nil {
		t.Fatal("the failed reload was silent, it must at least be reported")
	}
}

func TestReloadingStore_DeletedFileKeepsTheLastGoodTokens(t *testing.T) {
	s, path := newReloadingForTest(t, `[{"token":"tok-a","name":"a","roles":["admin"]}]`)
	ctx := context.Background()
	s.onError = func(error) {}

	if err := os.Remove(path); err != nil {
		t.Fatalf("removing the file: %v", err)
	}
	if _, err := s.Verify(ctx, "tok-a"); err != nil {
		t.Fatalf("removing the file dropped every token: %v", err)
	}
}

func TestReloadingStore_UnchangedFileIsNotReparsed(t *testing.T) {
	s, _ := newReloadingForTest(t, `[{"token":"tok-a","name":"a","roles":["admin"]}]`)
	ctx := context.Background()
	before := s.current
	for i := 0; i < 5; i++ {
		if _, err := s.Verify(ctx, "tok-a"); err != nil {
			t.Fatalf("Verify: %v", err)
		}
	}
	if s.current != before {
		t.Fatal("the store was rebuilt even though the file never changed")
	}
}

func TestStaticStore_ExpiredTokenDoesNotAuthenticate(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)
	store := NewStaticStoreWithOperators(map[string]Operator{
		"tok-expired": {Name: "old", Roles: []Role{RoleAdmin}, ExpiresAt: &past},
		"tok-valid":   {Name: "current", Roles: []Role{RoleAdmin}, ExpiresAt: &future},
		"tok-forever": {Name: "no-expiry", Roles: []Role{RoleAdmin}},
	})
	ctx := context.Background()

	if _, err := store.Verify(ctx, "tok-expired"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Verify(expired) = %v, want ErrInvalidToken", err)
	}
	if _, err := store.Verify(ctx, "tok-valid"); err != nil {
		t.Fatalf("Verify(not yet expired): %v", err)
	}
	if _, err := store.Verify(ctx, "tok-forever"); err != nil {
		t.Fatalf("Verify(no expiry): %v", err)
	}
}

func TestOperator_Expired(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	var noExpiry Operator
	if noExpiry.Expired(now) {
		t.Fatal("an operator with no expiry reports expired")
	}
	past := now.Add(-time.Second)
	if !(Operator{ExpiresAt: &past}).Expired(now) {
		t.Fatal("an expiry one second ago does not report expired")
	}
	// Exactly at the expiry counts as expired, same boundary
	// credentials.Credential.Effective uses.
	if !(Operator{ExpiresAt: &now}).Expired(now) {
		t.Fatal("an expiry exactly now does not report expired")
	}
	future := now.Add(time.Second)
	if (Operator{ExpiresAt: &future}).Expired(now) {
		t.Fatal("a future expiry reports expired")
	}
}

func TestFromEnv_ExpiresAtIsParsed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens.json")
	writeFile(t, path, `[{"token":"tok-a","name":"a","roles":["admin"],"expires_at":"2020-01-01T00:00:00Z"}]`)
	t.Setenv(envTokensPath, path)

	store, err := FromEnv()
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if _, err := store.Verify(context.Background(), "tok-a"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("a token that expired in 2020 still authenticates: %v", err)
	}
}

func TestFromEnv_MalformedExpiresAtIsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens.json")
	writeFile(t, path, `[{"token":"tok-a","name":"a","roles":["admin"],"expires_at":"next tuesday"}]`)
	t.Setenv(envTokensPath, path)
	if _, err := FromEnv(); err == nil {
		t.Fatal("a malformed expires_at was accepted, an unparseable expiry should fail at startup rather than silently never expiring")
	}
}
