package policy

import (
	"encoding/base64"
	"testing"
)

// clearTesseraEnv blanks every env var FromEnv reads before a test runs.
// t.Setenv saves and restores the previous value automatically at test
// cleanup, so this only needs to set, not remember anything itself, an
// empty string and "unset" read identically through os.Getenv for every
// check FromEnv makes (they all trim and compare to "").
func clearTesseraEnv(t *testing.T) {
	t.Helper()
	for _, name := range []string{envBaseURL, envSigningKey, envIssuer, envAudience, envSystemSubject} {
		t.Setenv(name, "")
	}
}

func TestFromEnv_NoBaseURL_ReturnsInMemoryClient(t *testing.T) {
	clearTesseraEnv(t)
	c, err := FromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := c.(*InMemoryClient); !ok {
		t.Fatalf("expected an *InMemoryClient when %s is unset, got %T", envBaseURL, c)
	}
}

func TestFromEnv_BaseURLWithoutSigningKey_IsAnError(t *testing.T) {
	clearTesseraEnv(t)
	t.Setenv(envBaseURL, "http://tessera:8080")
	if _, err := FromEnv(); err == nil {
		t.Fatal("expected an error, base URL was set with no signing key")
	}
}

func TestFromEnv_SigningKeyWithIncidentalWhitespace_StillDecodes(t *testing.T) {
	// A .env parser that doesn't trim around '=', or a value pasted with
	// a trailing space, must not turn a perfectly valid key into a
	// confusing "not valid base64" error, trim before decoding, not just
	// before the emptiness check.
	clearTesseraEnv(t)
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	t.Setenv(envBaseURL, "http://tessera:8080")
	t.Setenv(envSigningKey, "  "+base64.StdEncoding.EncodeToString(key)+"  ")

	c, err := FromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := c.(*TesseraHTTPClient); !ok {
		t.Fatalf("expected a *TesseraHTTPClient, got %T", c)
	}
}

func TestFromEnv_InvalidBase64SigningKey_IsAnError(t *testing.T) {
	clearTesseraEnv(t)
	t.Setenv(envBaseURL, "http://tessera:8080")
	t.Setenv(envSigningKey, "not valid base64!!")
	if _, err := FromEnv(); err == nil {
		t.Fatal("expected an error for invalid base64")
	}
}

func TestFromEnv_ValidConfig_ReturnsTesseraHTTPClientWithDefaults(t *testing.T) {
	clearTesseraEnv(t)
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	t.Setenv(envBaseURL, "http://tessera:8080")
	t.Setenv(envSigningKey, base64.StdEncoding.EncodeToString(key))

	c, err := FromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	tc, ok := c.(*TesseraHTTPClient)
	if !ok {
		t.Fatalf("expected a *TesseraHTTPClient, got %T", c)
	}
	if tc.issuer != defaultIssuer {
		t.Fatalf("expected the default issuer %q, got %q", defaultIssuer, tc.issuer)
	}
	if tc.audience != defaultAudience {
		t.Fatalf("expected the default audience %q, got %q", defaultAudience, tc.audience)
	}
	if tc.systemSubject != defaultSystemSubject {
		t.Fatalf("expected the default system subject %q, got %q", defaultSystemSubject, tc.systemSubject)
	}
}

func TestFromEnv_ExplicitIssuerAudienceSubject_OverrideDefaults(t *testing.T) {
	clearTesseraEnv(t)
	key := make([]byte, 32)
	t.Setenv(envBaseURL, "http://tessera:8080")
	t.Setenv(envSigningKey, base64.StdEncoding.EncodeToString(key))
	t.Setenv(envIssuer, "custom-issuer")
	t.Setenv(envAudience, "custom-audience")
	t.Setenv(envSystemSubject, "custom-system")

	c, err := FromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	tc := c.(*TesseraHTTPClient)
	if tc.issuer != "custom-issuer" || tc.audience != "custom-audience" || tc.systemSubject != "custom-system" {
		t.Fatalf("expected explicit overrides to win, got issuer=%q audience=%q systemSubject=%q", tc.issuer, tc.audience, tc.systemSubject)
	}
}
