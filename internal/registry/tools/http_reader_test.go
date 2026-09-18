package tools

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPReader_Get(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/tools/invoice-lookup" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Tool{Name: "invoice-lookup", RiskClass: RiskReadOnly, Owner: "bogdan"})
	}))
	defer srv.Close()

	reader := NewHTTPReader(srv.URL, "")
	tool, err := reader.Get(context.Background(), "invoice-lookup")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if tool.Name != "invoice-lookup" || tool.RiskClass != RiskReadOnly || tool.Owner != "bogdan" {
		t.Fatalf("got %+v, want the tool the server returned", tool)
	}
}

func TestHTTPReader_GetNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	reader := NewHTTPReader(srv.URL, "")
	_, err := reader.Get(context.Background(), "does-not-exist")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get on a 404: got %v, want ErrNotFound", err)
	}
}

func TestHTTPReader_GetUnexpectedStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	reader := NewHTTPReader(srv.URL, "")
	_, err := reader.Get(context.Background(), "invoice-lookup")
	if err == nil {
		t.Fatalf("Get on a 500: got nil error, want one, and not ErrNotFound, a server error is not the same as a not-found")
	}
	if errors.Is(err, ErrNotFound) {
		t.Fatalf("Get on a 500: got ErrNotFound, want a distinct error, a 500 does not mean the tool doesn't exist")
	}
}

func TestHTTPReader_GetTrimsTrailingSlashInBaseURL(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewEncoder(w).Encode(Tool{Name: "invoice-lookup"})
	}))
	defer srv.Close()

	reader := NewHTTPReader(srv.URL+"/", "")
	if _, err := reader.Get(context.Background(), "invoice-lookup"); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if gotPath != "/tools/invoice-lookup" {
		t.Fatalf("path = %q, want /tools/invoice-lookup (no double slash from a trailing slash in the base URL)", gotPath)
	}
}

var _ Reader = (*HTTPReader)(nil)

// TestHTTPReader_SendsTheConfiguredToken is the regression test for the
// reason this token exists. cmd/api authenticates its own surface, so a
// reader with no credential gets 401 on every catalog lookup and the
// gateway turns every tool call into a lookup error. That was not
// caught by any test here, because every test here used a stand-in
// server that never asked for a credential, and it was not caught by
// the compose stack either until someone actually called a tool
// through it.
func TestHTTPReader_SendsTheConfiguredToken(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Authorization")
		if got != "Bearer op-viewer" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(Tool{Name: "invoice.read"})
	}))
	defer srv.Close()

	reader := NewHTTPReader(srv.URL, "op-viewer")
	if _, err := reader.Get(context.Background(), "invoice.read"); err != nil {
		t.Fatalf("Get with a token: %v", err)
	}
	if got != "Bearer op-viewer" {
		t.Errorf("Authorization header = %q, want %q", got, "Bearer op-viewer")
	}
}

// TestHTTPReader_NoTokenSendsNoHeader keeps the unauthenticated case
// working, which is what a cmd/api running with
// NIA_ALLOW_UNAUTHENTICATED=1 expects, and makes sure the token is
// genuinely optional rather than sent as an empty bearer.
func TestHTTPReader_NoTokenSendsNoHeader(t *testing.T) {
	var seen bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, seen = r.Header["Authorization"]
		_ = json.NewEncoder(w).Encode(Tool{Name: "invoice.read"})
	}))
	defer srv.Close()

	reader := NewHTTPReader(srv.URL, "")
	if _, err := reader.Get(context.Background(), "invoice.read"); err != nil {
		t.Fatalf("Get without a token: %v", err)
	}
	if seen {
		t.Error("an Authorization header was sent when no token was configured")
	}
}

// TestHTTPReader_RefusedLookupSaysWhy guards the error message rather
// than the behaviour, deliberately. "unexpected status 401" is a true
// statement that sends the reader looking in the wrong place; the
// refusal has exactly one cause and the message should name it.
func TestHTTPReader_RefusedLookupSaysWhy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	_, err := NewHTTPReader(srv.URL, "").Get(context.Background(), "invoice.read")
	if err == nil {
		t.Fatal("a 401 from the catalog was not an error")
	}
	if !strings.Contains(err.Error(), envAPIToken) {
		t.Errorf("error %q does not name %s, which is the one thing that fixes it", err, envAPIToken)
	}
}
