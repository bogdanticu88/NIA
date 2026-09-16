package tools

import "testing"

func TestFromEnvReader_Unset_ReturnsNil(t *testing.T) {
	t.Setenv(envAPIURL, "")
	r, err := FromEnvReader()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r != nil {
		t.Fatalf("expected a nil Reader when %s is unset, got %T", envAPIURL, r)
	}
}

func TestFromEnvReader_Set_ReturnsHTTPReader(t *testing.T) {
	t.Setenv(envAPIURL, "http://localhost:8080")
	r, err := FromEnvReader()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := r.(*HTTPReader); !ok {
		t.Fatalf("expected an *HTTPReader when %s is set, got %T", envAPIURL, r)
	}
}

func TestFromEnvReader_WithIncidentalWhitespace_StillUsed(t *testing.T) {
	// Same trim-before-check discipline as audit.FromEnv and
	// policy.FromEnv: a value with leading or trailing whitespace from
	// a sloppy .env parser must not be treated as unset.
	t.Setenv(envAPIURL, "  http://localhost:8080  ")
	r, err := FromEnvReader()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r == nil {
		t.Fatal("expected a non-nil Reader, whitespace made this look unset")
	}
}
