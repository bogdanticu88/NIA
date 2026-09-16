package sensitivity

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFromEnvClassifier_Unset_NoRules(t *testing.T) {
	t.Setenv(envRulesPath, "")
	c, err := FromEnvClassifier()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := c.Classify("customer.ssn"); got != Public {
		t.Fatalf("Classify with FromEnvClassifier unset = %v, want Public", got)
	}
}

func TestFromEnvClassifier_MissingFile_IsAnError(t *testing.T) {
	t.Setenv(envRulesPath, filepath.Join(t.TempDir(), "does-not-exist.json"))
	if _, err := FromEnvClassifier(); err == nil {
		t.Fatal("expected an error for a missing rules file, got nil")
	}
}

func TestFromEnvClassifier_MalformedJSON_IsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.json")
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatalf("writing test fixture: %v", err)
	}
	t.Setenv(envRulesPath, path)
	if _, err := FromEnvClassifier(); err == nil {
		t.Fatal("expected an error for malformed JSON, got nil")
	}
}

func TestFromEnvClassifier_UnknownLevel_IsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.json")
	body := `[{"pattern":"customer.ssn","level":"top-secret"}]`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing test fixture: %v", err)
	}
	t.Setenv(envRulesPath, path)
	if _, err := FromEnvClassifier(); err == nil {
		t.Fatal("expected an error for an unknown level in the rules file, got nil")
	}
}

func TestFromEnvClassifier_EmptyPattern_IsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.json")
	body := `[{"pattern":"","level":"critical"}]`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing test fixture: %v", err)
	}
	t.Setenv(envRulesPath, path)
	if _, err := FromEnvClassifier(); err == nil {
		t.Fatal("expected an error for an empty pattern in the rules file, got nil")
	}
}

func TestFromEnvClassifier_ValidFile_LoadsRules(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.json")
	body := `[
		{"pattern":"customer.ssn","level":"critical"},
		{"pattern":"customer.*","level":"confidential"},
		{"pattern":"credential.*","level":"sensitive"}
	]`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing test fixture: %v", err)
	}
	t.Setenv(envRulesPath, path)

	c, err := FromEnvClassifier()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := c.Classify("customer.ssn"); got != Critical {
		t.Fatalf("Classify(customer.ssn) = %v, want Critical", got)
	}
	if got := c.Classify("customer.email"); got != Confidential {
		t.Fatalf("Classify(customer.email) = %v, want Confidential", got)
	}
	if got := c.Classify("credential.material"); got != Sensitive {
		t.Fatalf("Classify(credential.material) = %v, want Sensitive", got)
	}
	if got := c.Classify("invoice.total"); got != Public {
		t.Fatalf("Classify(invoice.total) = %v, want Public, no rule matches it", got)
	}
}
