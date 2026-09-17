package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestForwarderFromEnv_Unset_ReturnsNil(t *testing.T) {
	t.Setenv(envDownstreamURL, "")
	if f := forwarderFromEnv(); f != nil {
		t.Fatalf("forwarderFromEnv() = %v, want nil when %s is unset", f, envDownstreamURL)
	}
}

func TestForwarderFromEnv_Set_ReturnsHTTPForwarder(t *testing.T) {
	t.Setenv(envDownstreamURL, "http://localhost:9000")
	f := forwarderFromEnv()
	if _, ok := f.(*HTTPForwarder); !ok {
		t.Fatalf("forwarderFromEnv() = %T, want *HTTPForwarder when %s is set", f, envDownstreamURL)
	}
}

func TestForwarderFromEnv_WhitespaceIsTrimmed(t *testing.T) {
	// Same discipline as tools.FromEnvReader and every other FromEnv in
	// this codebase: a sloppy .env parser leaving whitespace around the
	// value must not make this look unset.
	t.Setenv(envDownstreamURL, "  http://localhost:9000  ")
	if f := forwarderFromEnv(); f == nil {
		t.Fatal("expected a non-nil Forwarder, whitespace made this look unset")
	}
}

func TestHTTPForwarder_SendsToolAndArgumentsAndReturnsWhatCameBack(t *testing.T) {
	var gotPath string
	var gotBody toolCallRequest
	downstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("decoding downstream request body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"invoice_total": 4200})
	}))
	defer downstream.Close()

	f := NewHTTPForwarder(downstream.URL)
	result, err := f.Forward(context.Background(), "invoice.read", map[string]any{"invoice_id": "INV-1"})
	if err != nil {
		t.Fatalf("Forward: %v", err)
	}

	if gotPath != "/invoice.read" {
		t.Fatalf("downstream saw path %q, want /invoice.read", gotPath)
	}
	if gotBody.Arguments["invoice_id"] != "INV-1" {
		t.Fatalf("downstream saw arguments %v, want invoice_id=INV-1", gotBody.Arguments)
	}
	if result.StatusCode != http.StatusOK {
		t.Fatalf("StatusCode = %d, want 200", result.StatusCode)
	}
	var decoded map[string]any
	if err := json.Unmarshal(result.Body, &decoded); err != nil {
		t.Fatalf("unmarshaling result body: %v", err)
	}
	if decoded["invoice_total"] != float64(4200) {
		t.Fatalf("decoded body = %v, want invoice_total=4200", decoded)
	}
}

func TestHTTPForwarder_DownstreamErrorStatusIsReturnedNotSwallowed(t *testing.T) {
	downstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"downstream exploded"}`))
	}))
	defer downstream.Close()

	f := NewHTTPForwarder(downstream.URL)
	result, err := f.Forward(context.Background(), "invoice.read", nil)
	if err != nil {
		t.Fatalf("Forward: %v, want no Go error, a downstream error status is not a transport failure", err)
	}
	if result.StatusCode != http.StatusInternalServerError {
		t.Fatalf("StatusCode = %d, want 500", result.StatusCode)
	}
	if msg, ok := downstreamReportedError(result.Body); !ok || msg != "downstream exploded" {
		t.Fatalf("downstreamReportedError(%s) = %q, %v, want \"downstream exploded\", true", result.Body, msg, ok)
	}
}

func TestHTTPForwarder_UnreachableDownstreamReturnsAnError(t *testing.T) {
	// A closed server, nothing is listening at this address anymore.
	downstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := downstream.URL
	downstream.Close()

	f := NewHTTPForwarder(url)
	_, err := f.Forward(context.Background(), "invoice.read", nil)
	if err == nil {
		t.Fatal("Forward: want an error when the downstream is unreachable, got nil")
	}
}

func TestHTTPForwarder_ResponseLargerThanCapIsTruncatedNotFailed(t *testing.T) {
	downstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		buf := make([]byte, maxDownstreamResponseBytes+1024)
		_, _ = w.Write(buf)
	}))
	defer downstream.Close()

	f := NewHTTPForwarder(downstream.URL)
	result, err := f.Forward(context.Background(), "big.dump", nil)
	if err != nil {
		t.Fatalf("Forward: %v, want a truncated read, not an error", err)
	}
	if len(result.Body) != maxDownstreamResponseBytes {
		t.Fatalf("len(result.Body) = %d, want exactly the %d byte cap", len(result.Body), maxDownstreamResponseBytes)
	}
}

func TestDownstreamReportedError_NonJSONBodyIsNotAnError(t *testing.T) {
	if _, ok := downstreamReportedError([]byte("plain text, not JSON at all")); ok {
		t.Fatal("downstreamReportedError on a non-JSON body, want ok=false")
	}
}

func TestDownstreamReportedError_JSONWithNoErrorFieldIsNotAnError(t *testing.T) {
	if _, ok := downstreamReportedError([]byte(`{"invoice_total":4200}`)); ok {
		t.Fatal("downstreamReportedError on a body with no error field, want ok=false")
	}
}

func TestHTTPForwarder_DurationIsRecorded(t *testing.T) {
	downstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer downstream.Close()

	f := NewHTTPForwarder(downstream.URL)
	result, err := f.Forward(context.Background(), "slow.tool", nil)
	if err != nil {
		t.Fatalf("Forward: %v", err)
	}
	if result.Duration <= 0 {
		t.Fatalf("Duration = %v, want a positive duration", result.Duration)
	}
}
