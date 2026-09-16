package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResourcePolicyFromEnv_Unset_NotConfigured(t *testing.T) {
	t.Setenv(envResourceRulesPath, "")
	p, err := resourcePolicyFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p != nil {
		t.Fatalf("got %v, want nil when %s is unset", p, envResourceRulesPath)
	}
}

func TestResourcePolicyFromEnv_MissingFile_IsAnError(t *testing.T) {
	t.Setenv(envResourceRulesPath, filepath.Join(t.TempDir(), "does-not-exist.json"))
	if _, err := resourcePolicyFromEnv(); err == nil {
		t.Fatal("expected an error for a missing rules file, got nil")
	}
}

func TestResourcePolicyFromEnv_MalformedJSON_IsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.json")
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatalf("writing test fixture: %v", err)
	}
	t.Setenv(envResourceRulesPath, path)
	if _, err := resourcePolicyFromEnv(); err == nil {
		t.Fatal("expected an error for malformed JSON, got nil")
	}
}

func TestResourcePolicyFromEnv_MissingTool_IsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.json")
	body := `[{"fields_field":"columns"}]`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing test fixture: %v", err)
	}
	t.Setenv(envResourceRulesPath, path)
	if _, err := resourcePolicyFromEnv(); err == nil {
		t.Fatal("expected an error for a rule missing tool, got nil")
	}
}

func TestResourcePolicyFromEnv_MissingFieldsField_IsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.json")
	body := `[{"tool":"database.query","qualifier_field":"table"}]`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing test fixture: %v", err)
	}
	t.Setenv(envResourceRulesPath, path)
	if _, err := resourcePolicyFromEnv(); err == nil {
		t.Fatal("expected an error for a rule missing fields_field, got nil")
	}
}

func TestResourcePolicyFromEnv_ValidFile_LoadsRules(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.json")
	body := `[{"tool":"database.query","qualifier_field":"table","fields_field":"columns"}]`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing test fixture: %v", err)
	}
	t.Setenv(envResourceRulesPath, path)

	p, err := resourcePolicyFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p == nil {
		t.Fatal("got nil policy, want a configured one")
	}
	got := p.Resources("database.query", map[string]any{"table": "customers", "columns": []any{"ssn"}})
	want := []string{"customers.ssn"}
	if !equalStrings(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}
