package policy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// capturedCheck is what the fake OpenFGA server saw, so a test can
// assert on the exact tuple NIA asked about rather than only on the
// answer it got back.
type capturedCheck struct {
	path string
	body checkRequestWire
}

func fakeOpenFGA(t *testing.T, allowed bool, captured *capturedCheck) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if captured != nil {
			captured.path = r.URL.Path
			_ = json.Unmarshal(raw, &captured.body)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(checkResponseWire{Allowed: allowed})
	}))
}

// recordingClient is the base Client an OpenFGAChecker wraps, so a test
// can prove Check does not fall through to it and that everything else
// does.
type recordingClient struct {
	*InMemoryClient
	checkCalls int
}

func (c *recordingClient) Check(ctx context.Context, agentRef string, grant Grant) (bool, error) {
	c.checkCalls++
	return c.InMemoryClient.Check(ctx, agentRef, grant)
}

func newRecordingClient() *recordingClient {
	return &recordingClient{InMemoryClient: NewInMemoryClient()}
}

func TestOpenFGAChecker_ToolGrant_AsksAboutTheTupleTesseraWouldHaveWritten(t *testing.T) {
	var got capturedCheck
	srv := fakeOpenFGA(t, true, &got)
	defer srv.Close()

	c := NewOpenFGAChecker(newRecordingClient(), srv.URL, "store-123", "model-abc")
	allowed, err := c.Check(context.Background(), "agent:Billing-Reconciler", GrantForTool("invoice.read"))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !allowed {
		t.Fatal("allowed = false, want true when OpenFGA says allowed")
	}

	if got.path != "/stores/store-123/check" {
		t.Fatalf("path = %q, want /stores/store-123/check", got.path)
	}
	// "agent:Billing-Reconciler" escapes its colon the way
	// TesseraHTTPClient does on the write side, then lowercases the way
	// Tessera's CanonicalForm.ClientRef does. Both transformations have
	// to happen or this names a user no tuple was ever written for.
	wantUser := "client:" + canonicalClientRef("agent:Billing-Reconciler")
	if got.body.TupleKey.User != wantUser {
		t.Fatalf("user = %q, want %q", got.body.TupleKey.User, wantUser)
	}
	if strings.Contains(got.body.TupleKey.User, ":") != true || strings.Contains(got.body.TupleKey.User, "billing") != true {
		t.Fatalf("user = %q, expected a lowercased client ref", got.body.TupleKey.User)
	}
	if got.body.TupleKey.Relation != "member" {
		t.Fatalf("relation = %q, want member", got.body.TupleKey.Relation)
	}
	if got.body.TupleKey.Object != "api_group:tool/invoice.read" {
		t.Fatalf("object = %q, want api_group:tool/invoice.read", got.body.TupleKey.Object)
	}
	if got.body.AuthorizationModelID != "model-abc" {
		t.Fatalf("authorization_model_id = %q, want model-abc", got.body.AuthorizationModelID)
	}
}

func TestOpenFGAChecker_DataGrant_UsesTheDataPrefix(t *testing.T) {
	var got capturedCheck
	srv := fakeOpenFGA(t, true, &got)
	defer srv.Close()

	c := NewOpenFGAChecker(newRecordingClient(), srv.URL, "store-123", "")
	if _, err := c.Check(context.Background(), "agent:billing", GrantForData("customers.ssn")); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if got.body.TupleKey.Object != "api_group:data/customers.ssn" {
		t.Fatalf("object = %q, want api_group:data/customers.ssn", got.body.TupleKey.Object)
	}
	if got.body.AuthorizationModelID != "" {
		t.Fatalf("authorization_model_id = %q, want empty when no model is configured", got.body.AuthorizationModelID)
	}
}

func TestOpenFGAChecker_NotAllowedIsADenialNotAnError(t *testing.T) {
	srv := fakeOpenFGA(t, false, nil)
	defer srv.Close()

	c := NewOpenFGAChecker(newRecordingClient(), srv.URL, "store-123", "")
	allowed, err := c.Check(context.Background(), "agent:billing", GrantForTool("invoice.read"))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if allowed {
		t.Fatal("allowed = true, want false when OpenFGA says not allowed")
	}
}

// TestOpenFGAChecker_CheckDoesNotFallThroughToTheBaseClient is the
// point of the whole type: the base client would answer from Tessera's
// declared grant list, which is exactly the stale answer this replaces.
func TestOpenFGAChecker_CheckDoesNotFallThroughToTheBaseClient(t *testing.T) {
	srv := fakeOpenFGA(t, false, nil)
	defer srv.Close()

	base := newRecordingClient()
	// Declare the grant on the base client, so a fall-through would
	// return true and be visibly wrong rather than coincidentally right.
	if err := base.WriteGrants(context.Background(), "agent:billing", []Grant{GrantForTool("invoice.read")}); err != nil {
		t.Fatalf("WriteGrants: %v", err)
	}

	c := NewOpenFGAChecker(base, srv.URL, "store-123", "")
	allowed, err := c.Check(context.Background(), "agent:billing", GrantForTool("invoice.read"))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if allowed {
		t.Fatal("allowed = true, the answer came from the base client's declared grants instead of OpenFGA")
	}
	if base.checkCalls != 0 {
		t.Fatalf("base Check was called %d times, want 0", base.checkCalls)
	}
}

func TestOpenFGAChecker_UnreachableOpenFGAIsAnErrorNotADenial(t *testing.T) {
	srv := fakeOpenFGA(t, true, nil)
	srv.Close() // closed before use, so the request cannot connect

	c := NewOpenFGAChecker(newRecordingClient(), srv.URL, "store-123", "")
	allowed, err := c.Check(context.Background(), "agent:billing", GrantForTool("invoice.read"))
	if err == nil {
		t.Fatal("err = nil, want an error: an unreachable authorization store is not a denial")
	}
	if allowed {
		t.Fatal("allowed = true alongside the error")
	}
}

func TestOpenFGAChecker_NonOKStatusIsAnErrorNotADenial(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"code":"validation_error"}`, http.StatusBadRequest)
	}))
	defer srv.Close()

	c := NewOpenFGAChecker(newRecordingClient(), srv.URL, "store-123", "")
	if _, err := c.Check(context.Background(), "agent:billing", GrantForTool("invoice.read")); err == nil {
		t.Fatal("err = nil, want an error for a non-200 response")
	}
}

func TestOpenFGAChecker_EndpointGrantIsRefusedRatherThanGuessed(t *testing.T) {
	srv := fakeOpenFGA(t, true, nil)
	defer srv.Close()

	c := NewOpenFGAChecker(newRecordingClient(), srv.URL, "store-123", "")
	_, err := c.Check(context.Background(), "agent:billing", GrantForEndpoint("GET", "/invoices/42"))
	if err == nil {
		t.Fatal("err = nil, want an error: the object name for an endpoint grant is not derivable without Tessera's endpoint catalog")
	}
	if !strings.Contains(err.Error(), "endpoint catalog") {
		t.Fatalf("err = %v, want it to name the reason", err)
	}
}

func TestOpenFGAChecker_EmptyObjectIsRefused(t *testing.T) {
	srv := fakeOpenFGA(t, true, nil)
	defer srv.Close()

	c := NewOpenFGAChecker(newRecordingClient(), srv.URL, "store-123", "")
	for _, g := range []Grant{{Kind: "tool"}, {Kind: "data"}, {Kind: "api_group"}, {Kind: "nonsense"}} {
		if _, err := c.Check(context.Background(), "agent:billing", g); err == nil {
			t.Fatalf("grant %+v was accepted, want an error", g)
		}
	}
}

// TestOpenFGAChecker_EverythingButCheckGoesToTheBaseClient keeps the
// boundary honest: Tessera stays the single writer, and the two reads
// that genuinely belong to it (the declared grant list, the kill
// sentinel) stay there too.
func TestOpenFGAChecker_EverythingButCheckGoesToTheBaseClient(t *testing.T) {
	srv := fakeOpenFGA(t, false, nil)
	defer srv.Close()

	base := newRecordingClient()
	c := NewOpenFGAChecker(base, srv.URL, "store-123", "")
	ctx := context.Background()

	if err := c.WriteGrants(ctx, "agent:billing", []Grant{GrantForTool("invoice.read")}); err != nil {
		t.Fatalf("WriteGrants: %v", err)
	}
	grants, err := c.ListGrants(ctx, "agent:billing")
	if err != nil || len(grants) != 1 {
		t.Fatalf("ListGrants = %v, %v, want the one grant written through the base client", grants, err)
	}
	if _, err := c.Kill(ctx, "agent:billing", "INC-1", "bogdan"); err != nil {
		t.Fatalf("Kill: %v", err)
	}
	killed, err := c.IsKilled(ctx, "agent:billing")
	if err != nil {
		t.Fatalf("IsKilled: %v", err)
	}
	if !killed {
		t.Fatal("IsKilled = false after Kill, the sentinel lives on the base client and must be read from there")
	}
	if err := c.Restore(ctx, "agent:billing", "bogdan"); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if err := c.DeleteGrants(ctx, "agent:billing", []Grant{GrantForTool("invoice.read")}); err != nil && !errors.Is(err, ErrKilled) {
		t.Fatalf("DeleteGrants: %v", err)
	}
}

func TestFromEnv_OpenFGAVariablesMustBeSetTogether(t *testing.T) {
	t.Setenv(envBaseURL, "http://tessera.invalid")
	t.Setenv(envSigningKey, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")

	t.Setenv(envOpenFGAURL, "http://openfga.invalid")
	t.Setenv(envOpenFGAStoreID, "")
	if _, err := FromEnv(); err == nil {
		t.Fatalf("%s alone was accepted, want an error rather than silently keeping the stale Check path", envOpenFGAURL)
	}

	t.Setenv(envOpenFGAURL, "")
	t.Setenv(envOpenFGAStoreID, "store-123")
	if _, err := FromEnv(); err == nil {
		t.Fatalf("%s alone was accepted, want an error", envOpenFGAStoreID)
	}
}

func TestFromEnv_BothOpenFGAVariablesSetReturnsACheckerOverTessera(t *testing.T) {
	t.Setenv(envBaseURL, "http://tessera.invalid")
	t.Setenv(envSigningKey, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	t.Setenv(envOpenFGAURL, "http://openfga.invalid")
	t.Setenv(envOpenFGAStoreID, "store-123")

	c, err := FromEnv()
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	checker, ok := c.(*OpenFGAChecker)
	if !ok {
		t.Fatalf("FromEnv returned %T, want *OpenFGAChecker", c)
	}
	if _, ok := checker.base.(*TesseraHTTPClient); !ok {
		t.Fatalf("base client is %T, want *TesseraHTTPClient", checker.base)
	}
}

func TestFromEnv_NeitherOpenFGAVariableSetIsUnchangedBehavior(t *testing.T) {
	t.Setenv(envBaseURL, "http://tessera.invalid")
	t.Setenv(envSigningKey, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	t.Setenv(envOpenFGAURL, "")
	t.Setenv(envOpenFGAStoreID, "")

	c, err := FromEnv()
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if _, ok := c.(*TesseraHTTPClient); !ok {
		t.Fatalf("FromEnv returned %T, want *TesseraHTTPClient when OpenFGA is not configured", c)
	}
}
