package opauth

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestFromEnv_UnsetReturnsNilStoreNoError(t *testing.T) {
	t.Setenv(envTokensPath, "")
	store, err := FromEnv()
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if store != nil {
		t.Fatalf("store = %v, want nil: unset must mean operator auth is off, not a Store that rejects everything", store)
	}
}

func TestFromEnv_ValidFileBuildsAWorkingStore(t *testing.T) {
	path := writeTokenFile(t, `[{"token":"tok-bogdan","name":"bogdan","roles":["admin"]},{"token":"tok-ci","name":"ci-pipeline","roles":["operator"]}]`)
	t.Setenv(envTokensPath, path)

	store, err := FromEnv()
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if store == nil {
		t.Fatalf("store is nil, want a real Store for a configured, valid file")
	}
	op, err := store.Verify(context.Background(), "tok-bogdan")
	if err != nil || op.Name != "bogdan" {
		t.Fatalf("got %+v, %v, want bogdan", op, err)
	}
}

func TestFromEnv_MissingFileIsAnError(t *testing.T) {
	t.Setenv(envTokensPath, filepath.Join(t.TempDir(), "does-not-exist.json"))
	if _, err := FromEnv(); err == nil {
		t.Fatalf("FromEnv returned no error for a missing file, want one: silently running with no operator auth after asking for it would be worse than failing to start")
	}
}

func TestFromEnv_MalformedJSONIsAnError(t *testing.T) {
	path := writeTokenFile(t, `not json`)
	t.Setenv(envTokensPath, path)
	if _, err := FromEnv(); err == nil {
		t.Fatalf("FromEnv returned no error for malformed JSON, want one")
	}
}

func TestFromEnv_EmptyFileIsAnError(t *testing.T) {
	path := writeTokenFile(t, `[]`)
	t.Setenv(envTokensPath, path)
	if _, err := FromEnv(); err == nil {
		t.Fatalf("FromEnv returned no error for an empty token list, want one: an operator who set this env var and ended up with zero valid tokens locked themselves out, that should fail loudly at startup, not quietly")
	}
}

func TestFromEnv_EmptyTokenFieldIsAnError(t *testing.T) {
	path := writeTokenFile(t, `[{"token":"","name":"bogdan"}]`)
	t.Setenv(envTokensPath, path)
	if _, err := FromEnv(); err == nil {
		t.Fatalf("FromEnv returned no error for an empty token field, want one")
	}
}

func TestFromEnv_EmptyNameFieldIsAnError(t *testing.T) {
	path := writeTokenFile(t, `[{"token":"tok-bogdan","name":""}]`)
	t.Setenv(envTokensPath, path)
	if _, err := FromEnv(); err == nil {
		t.Fatalf("FromEnv returned no error for an empty name field, want one: an unnamed operator defeats the point, the audit trail needs to say who")
	}
}

func writeTokenFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tokens.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write token file: %v", err)
	}
	return path
}

func TestFromEnvEnforced_UnsetIsAnErrorNotAnOpenProcess(t *testing.T) {
	t.Setenv(envTokensPath, "")
	t.Setenv(EnvAllowUnauthenticated, "")

	store, allowed, err := FromEnvEnforced()
	if err == nil {
		t.Fatalf("FromEnvEnforced() = (%v, %v, nil), want an error: an unset tokens path must not silently produce an unauthenticated process", store, allowed)
	}
	if store != nil || allowed {
		t.Fatalf("got store %v allowed %v alongside the error, want nil and false", store, allowed)
	}
}

func TestFromEnvEnforced_UnsetWithExplicitOptOutIsAllowed(t *testing.T) {
	t.Setenv(envTokensPath, "")
	t.Setenv(EnvAllowUnauthenticated, "1")

	store, allowed, err := FromEnvEnforced()
	if err != nil {
		t.Fatalf("FromEnvEnforced: %v", err)
	}
	if store != nil {
		t.Fatalf("store = %v, want nil when running unauthenticated on purpose", store)
	}
	if !allowed {
		t.Fatal("allowedUnauthenticated = false, want true so the caller can log the difference")
	}
}

func TestFromEnvEnforced_AnyOtherOptOutValueStillFails(t *testing.T) {
	// Only "1" opts out. "true", "yes", and an accidental empty-ish
	// value must not, a deployment shouldn't be able to disable
	// authentication by almost setting a variable.
	for _, v := range []string{"true", "yes", "0", " 1", "TRUE"} {
		t.Setenv(envTokensPath, "")
		t.Setenv(EnvAllowUnauthenticated, v)
		if _, _, err := FromEnvEnforced(); err == nil {
			t.Fatalf("%s=%q was accepted as an opt out, want only \"1\" to count", EnvAllowUnauthenticated, v)
		}
	}
}

func TestFromEnvEnforced_ValidFileReturnsAStoreAndNoOptOut(t *testing.T) {
	path := writeTokenFile(t, `[{"token":"tok-a","name":"bogdan","roles":["admin"]}]`)
	t.Setenv(envTokensPath, path)
	t.Setenv(EnvAllowUnauthenticated, "")

	store, allowed, err := FromEnvEnforced()
	if err != nil {
		t.Fatalf("FromEnvEnforced: %v", err)
	}
	if store == nil {
		t.Fatal("store is nil, want a usable store")
	}
	if allowed {
		t.Fatal("allowedUnauthenticated = true, want false when a real tokens file is configured")
	}
	if _, err := store.Verify(context.Background(), "tok-a"); err != nil {
		t.Fatalf("Verify with the configured token: %v", err)
	}
}
