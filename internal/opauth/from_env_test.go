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
	path := writeTokenFile(t, `[{"token":"tok-bogdan","name":"bogdan"},{"token":"tok-ci","name":"ci-pipeline"}]`)
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
