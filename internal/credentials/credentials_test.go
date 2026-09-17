package credentials

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestCredential_JSONNeverCarriesTheSecretHash is the directive's own
// requirement, "credential hashes/digests must not be exposed through
// APIs or logs," checked at the one place that actually decides it:
// SecretHash's own json tag. Every handler in cmd/api that returns a
// Credential (handleIssueCredential, handleListCredentials, and the
// rest) goes through this exact same encoding/json call, so this is
// the real, narrow surface, not an approximation of it.
func TestCredential_JSONNeverCarriesTheSecretHash(t *testing.T) {
	cred := Credential{
		ID:         "cred-1",
		AgentRef:   "agent:billing",
		Kind:       KindAPIKey,
		Status:     StatusActive,
		SecretHash: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
		IssuedAt:   time.Now(),
	}
	body, err := json.Marshal(cred)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(body), "SecretHash") {
		t.Fatalf("JSON body contains the SecretHash field name: %s", body)
	}
	if strings.Contains(string(body), cred.SecretHash) {
		t.Fatalf("JSON body contains the digest value itself: %s", body)
	}

	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if _, present := decoded["SecretHash"]; present {
		t.Fatalf("decoded JSON has a SecretHash key at all, want it entirely absent: %v", decoded)
	}
}
