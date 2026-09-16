package tools

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
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

	reader := NewHTTPReader(srv.URL)
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

	reader := NewHTTPReader(srv.URL)
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

	reader := NewHTTPReader(srv.URL)
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

	reader := NewHTTPReader(srv.URL + "/")
	if _, err := reader.Get(context.Background(), "invoice-lookup"); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if gotPath != "/tools/invoice-lookup" {
		t.Fatalf("path = %q, want /tools/invoice-lookup (no double slash from a trailing slash in the base URL)", gotPath)
	}
}

var _ Reader = (*HTTPReader)(nil)
