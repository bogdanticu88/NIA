package policy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testIssuer   = "nia-test"
	testAudience = "nia-test-clients"
)

func testSigningKey() []byte {
	return []byte("0123456789abcdef0123456789abcdef") // 33 bytes, >= the 32 byte minimum
}

func newTestClient(t *testing.T, handler http.HandlerFunc) (*TesseraHTTPClient, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	c, err := NewTesseraHTTPClient(srv.URL, srv.Client(), testSigningKey(), testIssuer, testAudience, "nia-system")
	if err != nil {
		t.Fatalf("NewTesseraHTTPClient: %v", err)
	}
	return c, srv
}

// --- construction ---

func TestNewTesseraHTTPClient_RejectsMissingFields(t *testing.T) {
	key := testSigningKey()
	cases := []struct {
		name                                     string
		baseURL, issuer, audience, systemSubject string
		key                                      []byte
	}{
		{"empty base URL", "", testIssuer, testAudience, "sys", key},
		{"short signing key", "http://x", testIssuer, testAudience, "sys", []byte("too-short")},
		{"empty issuer", "http://x", "", testAudience, "sys", key},
		{"empty audience", "http://x", testIssuer, "", "sys", key},
		{"empty system subject", "http://x", testIssuer, testAudience, "", key},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewTesseraHTTPClient(tc.baseURL, nil, tc.key, tc.issuer, tc.audience, tc.systemSubject)
			if err == nil {
				t.Fatalf("expected an error, got none")
			}
		})
	}
}

func TestNewTesseraHTTPClient_NilHTTPClientGetsADefault(t *testing.T) {
	c, err := NewTesseraHTTPClient("http://example.invalid", nil, testSigningKey(), testIssuer, testAudience, "sys")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.httpClient == nil {
		t.Fatal("expected a default http.Client to be set")
	}
}

// --- token minting, checked against a real HS256 verification, not just "a token came out" ---

func TestMintToken_ProducesAThreePartTokenWithExpectedClaims(t *testing.T) {
	c, err := NewTesseraHTTPClient("http://x", nil, testSigningKey(), testIssuer, testAudience, "sys")
	if err != nil {
		t.Fatalf("NewTesseraHTTPClient: %v", err)
	}
	tok, err := c.mintToken("operator-1")
	if err != nil {
		t.Fatalf("mintToken: %v", err)
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("expected a three part JWT, got %d parts", len(parts))
	}
}

func TestMintToken_RejectsEmptySubject(t *testing.T) {
	c, _ := NewTesseraHTTPClient("http://x", nil, testSigningKey(), testIssuer, testAudience, "sys")
	if _, err := c.mintToken(""); err == nil {
		t.Fatal("expected an error minting a token with an empty subject")
	}
}

// --- request/response plumbing against a real HTTP server ---

func TestGetClientState_Found(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/clients/agent-1" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if auth := r.Header.Get("Authorization"); !strings.HasPrefix(auth, "Bearer ") {
			t.Fatalf("expected a bearer token, got %q", auth)
		}
		writeJSON(w, http.StatusOK, getClientResultWire{
			Outcome: "found",
			Client: &clientStateWire{
				ClientRef:    "agent-1",
				BusinessUnit: "finance",
				Killed:       false,
				Grants:       []wireGrant{{ApiGroup: "orders"}},
			},
		})
	})

	state, found, err := c.getClientState(context.Background(), "agent-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !found {
		t.Fatal("expected found=true")
	}
	if state.ClientRef != "agent-1" || state.BusinessUnit != "finance" {
		t.Fatalf("unexpected state: %+v", state)
	}
}

func TestGetClientState_NotFound(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusNotFound, getClientResultWire{Outcome: "not_found"})
	})

	_, found, err := c.getClientState(context.Background(), "never-onboarded")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found {
		t.Fatal("expected found=false")
	}
}

func TestGetClientState_InvalidRef_ReturnsErrorNotFoundFalse(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusBadRequest, getClientResultWire{Outcome: "invalid_client_ref", ErrorMessage: "client_ref contains an invalid character"})
	})

	_, found, err := c.getClientState(context.Background(), "has a space")
	if err == nil {
		t.Fatal("expected an error for an invalid client_ref")
	}
	if found {
		t.Fatal("an invalid ref must not report found=true")
	}
	if !strings.Contains(err.Error(), "invalid character") {
		t.Fatalf("expected the server's error message to surface, got: %v", err)
	}
}

func TestDo_UnexpectedStatusCode_ReturnsErrorWithBody(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"internal server error"}`))
	})

	_, _, err := c.getClientState(context.Background(), "agent-1")
	if err == nil {
		t.Fatal("expected an error for a 500 response")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Fatalf("expected the status code in the error, got: %v", err)
	}
}

func TestDo_MalformedJSONResponse_ReturnsErrorNotPanic(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{not valid json`))
	})

	_, _, err := c.getClientState(context.Background(), "agent-1")
	if err == nil {
		t.Fatal("expected an error decoding malformed JSON")
	}
}

func TestDo_NetworkFailure_PropagatesNotSwallowed(t *testing.T) {
	// A client pointed at a server that immediately closes the connection
	// is the simplest reliable way to force a transport-level error
	// without relying on an unroutable address and a timeout.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("test server does not support hijacking")
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			t.Fatalf("hijack: %v", err)
		}
		conn.Close()
	}))
	defer srv.Close()

	c, err := NewTesseraHTTPClient(srv.URL, srv.Client(), testSigningKey(), testIssuer, testAudience, "sys")
	if err != nil {
		t.Fatalf("NewTesseraHTTPClient: %v", err)
	}

	_, _, err = c.getClientState(context.Background(), "agent-1")
	if err == nil {
		t.Fatal("expected a network error, got none")
	}
}

func TestDo_ContextCancellation_PropagatesAsError(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
			t.Error("handler did not observe client cancellation in time")
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _, err := c.getClientState(ctx, "agent-1")
	if err == nil {
		t.Fatal("expected a context cancellation error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected errors.Is(err, context.Canceled), got: %v", err)
	}
}

func TestDo_ResponseLargerThanLimit_IsTruncatedNotUnbounded(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		chunk := make([]byte, 1024)
		for i := range chunk {
			chunk[i] = 'a'
		}
		for written := 0; written < maxResponseBytes+2*len(chunk); written += len(chunk) {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	})

	// This response is not valid JSON (it's a wall of 'a's), so the real
	// assertion is that this returns promptly with a decode error rather
	// than hanging or exhausting memory reading an unbounded body.
	done := make(chan struct{})
	go func() {
		_, _, _ = c.getClientState(context.Background(), "agent-1")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("request did not complete, response reading may be unbounded")
	}
}

// --- WriteGrants: read-modify-write semantics ---

func TestWriteGrants_MergesWithExistingGrantsAndPreservesBusinessUnit(t *testing.T) {
	var onboardBody onboardRequestBody
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet:
			writeJSON(w, http.StatusOK, getClientResultWire{
				Outcome: "found",
				Client: &clientStateWire{
					ClientRef:    "agent-1",
					BusinessUnit: "finance",
					Grants:       []wireGrant{{ApiGroup: "orders"}},
				},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/clients/onboard":
			if err := json.NewDecoder(r.Body).Decode(&onboardBody); err != nil {
				t.Fatalf("decoding onboard body: %v", err)
			}
			writeJSON(w, http.StatusOK, onboardResultWire{
				Success: true,
				Client:  &clientStateWire{ClientRef: "agent-1", BusinessUnit: onboardBody.BusinessUnit, Grants: onboardBody.Grants},
			})
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	})

	err := c.WriteGrants(context.Background(), "agent-1", []Grant{GrantForAPIGroup("billing")})
	if err != nil {
		t.Fatalf("WriteGrants: %v", err)
	}
	if onboardBody.BusinessUnit != "finance" {
		t.Fatalf("expected business_unit to be preserved from the read, got %q", onboardBody.BusinessUnit)
	}
	if len(onboardBody.Grants) != 2 {
		t.Fatalf("expected the existing grant plus the new one, got %v", onboardBody.Grants)
	}
}

func TestWriteGrants_AgainstKilledClient_ReturnsErrKilledWithoutCallingOnboard(t *testing.T) {
	onboardCalled := false
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			writeJSON(w, http.StatusOK, getClientResultWire{
				Outcome: "found",
				Client:  &clientStateWire{ClientRef: "agent-1", Killed: true},
			})
			return
		}
		onboardCalled = true
		writeJSON(w, http.StatusOK, onboardResultWire{Success: true})
	})

	err := c.WriteGrants(context.Background(), "agent-1", []Grant{GrantForAPIGroup("billing")})
	if !errors.Is(err, ErrKilled) {
		t.Fatalf("expected ErrKilled, got: %v", err)
	}
	if onboardCalled {
		t.Fatal("onboard should never be called once the read shows the client is killed, the in-memory client makes the same call before touching state")
	}
}

func TestWriteGrants_KilledConcurrentlyBetweenReadAndWrite_ReturnsErrKilled(t *testing.T) {
	// The read says alive, but by the time onboard runs, Tessera reports
	// the warning that means the client was killed in between and the
	// write did not apply. That must not come back as success.
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			writeJSON(w, http.StatusOK, getClientResultWire{
				Outcome: "found",
				Client:  &clientStateWire{ClientRef: "agent-1", Killed: false},
			})
			return
		}
		writeJSON(w, http.StatusOK, onboardResultWire{
			Success: true,
			Warning: "client is killed, grants were not applied, restore the client first if new grants should take effect",
			Client:  &clientStateWire{ClientRef: "agent-1", Killed: true},
		})
	})

	err := c.WriteGrants(context.Background(), "agent-1", []Grant{GrantForAPIGroup("billing")})
	if !errors.Is(err, ErrKilled) {
		t.Fatalf("expected ErrKilled surfaced from the onboard warning, got: %v", err)
	}
}

func TestWriteGrants_OnboardFailure_ReturnsErrorWithServerMessage(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			writeJSON(w, http.StatusNotFound, getClientResultWire{Outcome: "not_found"})
			return
		}
		writeJSON(w, http.StatusBadRequest, onboardResultWire{Success: false, ErrorMessage: "client_ref must not be empty"})
	})

	err := c.WriteGrants(context.Background(), "agent-1", []Grant{GrantForAPIGroup("billing")})
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "client_ref must not be empty") {
		t.Fatalf("expected the server's error message to surface, got: %v", err)
	}
}

func TestWriteGrants_UnknownGrantKind_FailsBeforeAnyHTTPCall(t *testing.T) {
	called := int32(0)
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&called, 1)
		writeJSON(w, http.StatusNotFound, getClientResultWire{Outcome: "not_found"})
	})

	err := c.WriteGrants(context.Background(), "agent-1", []Grant{{Kind: "nonsense"}})
	if err == nil {
		t.Fatal("expected an error for an unknown grant kind")
	}
	// The GET happens before grants are validated (validation only
	// matters once there's something to merge and send), so allow that
	// one call, but onboard must never be reached with a bad grant.
	if atomic.LoadInt32(&called) > 1 {
		t.Fatalf("expected at most the GET call, got %d requests", called)
	}
}

func TestWriteGrants_ApiGroupCollidingWithToolPrefix_IsRejected(t *testing.T) {
	postCalled := false
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			writeJSON(w, http.StatusNotFound, getClientResultWire{Outcome: "not_found"})
			return
		}
		postCalled = true
		writeJSON(w, http.StatusOK, onboardResultWire{Success: true})
	})

	err := c.WriteGrants(context.Background(), "agent-1", []Grant{GrantForAPIGroup("tool:reports")})
	if err == nil {
		t.Fatal("expected an error, an api_group named tool:reports would come back misread as a tool grant")
	}
	if postCalled {
		t.Fatal("onboard must never be called with a grant that would round trip as the wrong kind")
	}
}

func TestWriteGrants_ReDeclaringAnAlreadyPresentGrant_StillCallsOnboard(t *testing.T) {
	// This looks like it should be skippable, the declared grant set
	// doesn't change, but Kill does not clear a client's declared grants
	// in the registry, only its live OpenFGA tuples and the kill
	// sentinel (confirmed against the real service in
	// tessera_client_live_test.go). So "the declared list already says
	// orders" does not mean orders is actually authorized right now, an
	// intervening kill and restore can desync the two without this
	// client ever seeing it in the GET response. WriteGrants has to call
	// onboard here so the server reconciles live state back to declared
	// state, skipping it would silently leave the agent unauthorized
	// while ListGrants and Check both kept reporting it as granted.
	postCalled := false
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			writeJSON(w, http.StatusOK, getClientResultWire{
				Outcome: "found",
				Client:  &clientStateWire{ClientRef: "agent-1", Grants: []wireGrant{{ApiGroup: "orders"}}},
			})
			return
		}
		postCalled = true
		writeJSON(w, http.StatusOK, onboardResultWire{Success: true})
	})

	if err := c.WriteGrants(context.Background(), "agent-1", []Grant{GrantForAPIGroup("orders")}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !postCalled {
		t.Fatal("expected onboard to be called even though the declared grant set doesn't change, it's what repairs kill/restore drift")
	}
}

func TestWriteGrants_EmptyGrantsAgainstNeverOnboardedAgent_DoesNotPhantomOnboard(t *testing.T) {
	postCalled := false
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			writeJSON(w, http.StatusNotFound, getClientResultWire{Outcome: "not_found"})
			return
		}
		postCalled = true
		writeJSON(w, http.StatusOK, onboardResultWire{Success: true})
	})

	if err := c.WriteGrants(context.Background(), "never-onboarded", nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if postCalled {
		t.Fatal("an empty WriteGrants call against an agentRef that doesn't exist yet must not create a phantom Tessera client record")
	}
}

// --- DeleteGrants ---

func TestDeleteGrants_UnknownAgent_IsANoOp(t *testing.T) {
	postCalled := false
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			postCalled = true
		}
		writeJSON(w, http.StatusNotFound, getClientResultWire{Outcome: "not_found"})
	})

	if err := c.DeleteGrants(context.Background(), "never-onboarded", []Grant{GrantForAPIGroup("x")}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if postCalled {
		t.Fatal("deleting from an agent that was never onboarded should not call onboard")
	}
}

func TestDeleteGrants_NothingToRemove_SkipsOnboardCall(t *testing.T) {
	postCalled := false
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			postCalled = true
			writeJSON(w, http.StatusOK, onboardResultWire{Success: true})
			return
		}
		writeJSON(w, http.StatusOK, getClientResultWire{
			Outcome: "found",
			Client:  &clientStateWire{ClientRef: "agent-1", Grants: []wireGrant{{ApiGroup: "orders"}}},
		})
	})

	if err := c.DeleteGrants(context.Background(), "agent-1", []Grant{GrantForAPIGroup("billing")}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if postCalled {
		t.Fatal("deleting a grant that isn't present should not need an onboard round trip")
	}
}

func TestDeleteGrants_RemovesOnlyTheRequestedGrant(t *testing.T) {
	var onboardBody onboardRequestBody
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			writeJSON(w, http.StatusOK, getClientResultWire{
				Outcome: "found",
				Client: &clientStateWire{
					ClientRef: "agent-1",
					Grants:    []wireGrant{{ApiGroup: "orders"}, {ApiGroup: "billing"}},
				},
			})
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&onboardBody)
		writeJSON(w, http.StatusOK, onboardResultWire{Success: true})
	})

	if err := c.DeleteGrants(context.Background(), "agent-1", []Grant{GrantForAPIGroup("billing")}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(onboardBody.Grants) != 1 || onboardBody.Grants[0].ApiGroup != "orders" {
		t.Fatalf("expected only 'orders' to remain, got %v", onboardBody.Grants)
	}
}

// --- Kill: operator attribution ---

func TestKill_SignsTheTokenWithTheGivenOperatorAsSubject(t *testing.T) {
	var sawSubject string
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/clients/agent-1/kill" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		sawSubject = subjectFromAuthHeader(t, r, testSigningKey())
		writeJSON(w, http.StatusOK, killResultWire{Success: true, ClientRef: "agent-1", TuplesDeleted: 3})
	})

	result, err := c.Kill(context.Background(), "agent-1", "INC-1", "alice")
	if err != nil {
		t.Fatalf("Kill: %v", err)
	}
	if result.TuplesDeleted != 3 {
		t.Fatalf("expected 3 tuples deleted, got %d", result.TuplesDeleted)
	}
	if sawSubject != "alice" {
		t.Fatalf("expected the kill token's subject to be the operator 'alice', got %q", sawSubject)
	}
}

func TestKill_EmptyOperator_RejectedBeforeAnyRequest(t *testing.T) {
	called := false
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		called = true
	})
	_, err := c.Kill(context.Background(), "agent-1", "INC-1", "")
	if err == nil {
		t.Fatal("expected an error for an empty operator")
	}
	if called {
		t.Fatal("must not call tessera with no operator to attribute the kill to")
	}
}

func TestKill_ServerFailure_ReturnsError(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusBadRequest, killResultWire{Success: false, ErrorMessage: "incident is required"})
	})
	_, err := c.Kill(context.Background(), "agent-1", "", "alice")
	if err == nil || !strings.Contains(err.Error(), "incident is required") {
		t.Fatalf("expected the server's error message to surface, got: %v", err)
	}
}

// --- Restore uses the system subject, not a caller operator (interface has none) ---

func TestRestore_SignsTheTokenWithTheSystemSubject(t *testing.T) {
	var sawSubject string
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		sawSubject = subjectFromAuthHeader(t, r, testSigningKey())
		writeJSON(w, http.StatusOK, restoreResultWire{Success: true, ClientRef: "agent-1"})
	})
	if err := c.Restore(context.Background(), "agent-1"); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if sawSubject != "nia-system" {
		t.Fatalf("expected the configured system subject, got %q", sawSubject)
	}
}

// --- Check / IsKilled / ListGrants against a killed and an unknown agent ---

func TestCheck_KilledAgent_ReturnsFalseNotError(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, getClientResultWire{
			Outcome: "found",
			Client:  &clientStateWire{ClientRef: "agent-1", Killed: true, Grants: []wireGrant{{ApiGroup: "billing"}}},
		})
	})
	allowed, err := c.Check(context.Background(), "agent-1", GrantForAPIGroup("billing"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if allowed {
		t.Fatal("a killed agent must never be allowed, even if the grant is still declared")
	}
}

func TestCheck_UnknownAgent_ReturnsFalseNotError(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusNotFound, getClientResultWire{Outcome: "not_found"})
	})
	allowed, err := c.Check(context.Background(), "never-onboarded", GrantForAPIGroup("billing"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if allowed {
		t.Fatal("an agent that was never onboarded must never be allowed")
	}
}

func TestIsKilled_UnknownAgent_ReturnsFalseNotError(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusNotFound, getClientResultWire{Outcome: "not_found"})
	})
	killed, err := c.IsKilled(context.Background(), "never-onboarded")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if killed {
		t.Fatal("an agent that was never onboarded is not killed")
	}
}

func TestListGrants_UnknownAgent_ReturnsEmptySliceNotError(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusNotFound, getClientResultWire{Outcome: "not_found"})
	})
	grants, err := c.ListGrants(context.Background(), "never-onboarded")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(grants) != 0 {
		t.Fatalf("expected an empty slice, got %v", grants)
	}
}

// --- tool/data grant wire encoding round trip ---

func TestGrantWireEncoding_ToolAndDataRoundTrip(t *testing.T) {
	in := []Grant{
		GrantForAPIGroup("orders"),
		GrantForEndpoint("get", "orders/{param}"),
		GrantForTool("mcp-search"),
		GrantForData("customer-records"),
	}
	wire, err := grantsToWireGrants(in)
	if err != nil {
		t.Fatalf("grantsToWireGrants: %v", err)
	}
	back, err := wireGrantsToGrants(wire)
	if err != nil {
		t.Fatalf("wireGrantsToGrants: %v", err)
	}
	if len(back) != len(in) {
		t.Fatalf("expected %d grants back, got %d: %v", len(in), len(back), back)
	}
	for i := range in {
		if back[i] != in[i] {
			t.Fatalf("grant %d did not round trip: sent %+v, got back %+v", i, in[i], back[i])
		}
	}
}

func TestGrantWireEncoding_ToolGrantUsesPrefixedApiGroupOnTheWire(t *testing.T) {
	wire, err := grantsToWireGrants([]Grant{GrantForTool("mcp-search")})
	if err != nil {
		t.Fatalf("grantsToWireGrants: %v", err)
	}
	if wire[0].ApiGroup != "tool:mcp-search" {
		t.Fatalf("expected the tool grant to be sent as a prefixed api_group so Tessera's wire format doesn't need to change, got %+v", wire[0])
	}
}

func TestWireGrantsToGrants_NeitherApiGroupNorPath_IsAnError(t *testing.T) {
	_, err := wireGrantsToGrants([]wireGrant{{}})
	if err == nil {
		t.Fatal("expected an error decoding a grant with neither api_group nor method+path")
	}
}

// --- per-agentRef locking actually serializes concurrent writers ---

func TestWriteGrants_ConcurrentCallsToSameAgentAreSerialized(t *testing.T) {
	var mu sync.Mutex
	inFlight := 0
	maxObservedInFlight := 0
	var state clientStateWire
	state.ClientRef = "agent-1"

	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			mu.Lock()
			snapshot := state
			mu.Unlock()
			writeJSON(w, http.StatusOK, getClientResultWire{Outcome: "found", Client: &snapshot})
			return
		}

		mu.Lock()
		inFlight++
		if inFlight > maxObservedInFlight {
			maxObservedInFlight = inFlight
		}
		mu.Unlock()

		// Give a second goroutine a real chance to race onto this
		// handler if the client-side lock isn't actually serializing.
		time.Sleep(20 * time.Millisecond)

		var body onboardRequestBody
		_ = json.NewDecoder(r.Body).Decode(&body)

		mu.Lock()
		state.Grants = body.Grants
		inFlight--
		mu.Unlock()

		writeJSON(w, http.StatusOK, onboardResultWire{Success: true})
	})

	const n = 8
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = c.WriteGrants(context.Background(), "agent-1", []Grant{GrantForAPIGroup("g")})
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("WriteGrants goroutine %d: %v", i, err)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if maxObservedInFlight > 1 {
		t.Fatalf("expected onboard calls for the same agentRef to be serialized by the client-side lock, observed %d concurrent", maxObservedInFlight)
	}
}

func TestWriteGrants_DifferentAgentsAreNotSerializedAgainstEachOther(t *testing.T) {
	release := make(chan struct{})
	agent1Reached := make(chan struct{})
	var agent1ReachedOnce sync.Once

	// Both agents' onboard calls land on the same route, POST
	// /clients/onboard, clientRef only shows up in the body, so the only
	// way to block just agent-1's call is to look at the body, a URL
	// path check would not distinguish them (and blocking on a
	// sync.Once here would be wrong for a different reason: a second
	// concurrent Do call blocks until the first's function returns, it
	// does not skip, that would recreate the exact hang this test is
	// checking doesn't happen).
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			writeJSON(w, http.StatusNotFound, getClientResultWire{Outcome: "not_found"})
			return
		}
		var body onboardRequestBody
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decoding onboard body: %v", err)
		}
		if body.ClientRef == "agent-1" {
			agent1ReachedOnce.Do(func() { close(agent1Reached) })
			<-release // hold agent-1's write open until agent-2's has been proven not to block on it
		}
		writeJSON(w, http.StatusOK, onboardResultWire{Success: true})
	})

	done := make(chan error, 1)
	go func() {
		done <- c.WriteGrants(context.Background(), "agent-1", []Grant{GrantForAPIGroup("g")})
	}()

	select {
	case <-agent1Reached:
	case <-time.After(2 * time.Second):
		t.Fatal("agent-1's onboard call never reached the server")
	}

	// agent-2 must not be blocked behind agent-1's held lock, that would
	// mean this client serializes on something coarser than per-agentRef.
	secondDone := make(chan error, 1)
	go func() {
		secondDone <- c.WriteGrants(context.Background(), "agent-2", []Grant{GrantForAPIGroup("g")})
	}()

	select {
	case err := <-secondDone:
		if err != nil {
			t.Fatalf("WriteGrants for agent-2: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("agent-2's write was blocked behind agent-1's lock, locking is not per-agentRef")
	}

	close(release)
	if err := <-done; err != nil {
		t.Fatalf("WriteGrants for agent-1: %v", err)
	}
}

// --- client_ref encoding: agentRef "agent:x" against Tessera's charset ---

func TestClientRefEncoding_RoundTrip(t *testing.T) {
	cases := []string{
		"agent:billing-reconciler",
		"agent:e2e-test",
		"no-colon-at-all",
		"my.service",
		"my_c_service", // deliberately contains the literal escape tokens as plain text
		"a.b.c:d.e.f",  // multiple dots and one colon
		"weird::double::colon",
		"",
		".",
		":",
		"..",
		"::",
	}
	for _, agentRef := range cases {
		t.Run(agentRef, func(t *testing.T) {
			encoded := encodeClientRef(agentRef)
			decoded, err := decodeClientRef(encoded)
			if err != nil {
				t.Fatalf("decodeClientRef(%q): %v", encoded, err)
			}
			if decoded != agentRef {
				t.Fatalf("round trip mismatch: original %q, encoded %q, decoded back to %q", agentRef, encoded, decoded)
			}
		})
	}
}

func TestClientRefEncoding_EncodedFormStaysWithinTesseraCharset(t *testing.T) {
	// Mirrors CanonicalForm.ClientRef on the Tessera side: ASCII
	// letters, digits, '.', '_', and '-' only. Anything else in the
	// encoded output would still fail against the real service.
	isAllowed := func(r rune) bool {
		return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-'
	}
	for _, agentRef := range []string{"agent:billing-reconciler", "agent:e2e-test", "a.b:c", "::::"} {
		encoded := encodeClientRef(agentRef)
		for _, r := range encoded {
			if !isAllowed(r) {
				t.Fatalf("encodeClientRef(%q) = %q contains %q, which Tessera's client_ref charset does not allow", agentRef, encoded, r)
			}
		}
	}
}

func TestClientRefEncoding_DistinctInputsNeverProduceTheSameEncoding(t *testing.T) {
	// Adversarial set: every input here shares characters with the
	// escape scheme itself (the escape rune '.', the letter 'c' that
	// follows it for an escaped colon, actual colons, and combinations
	// designed to look like an escape sequence once another one is
	// inserted next to it). A scheme that escapes by substituting
	// multi-character tokens can make two different inputs collide onto
	// the same output once the substitutions land next to each other;
	// this package's scheme (a single escape rune, exactly one rune of
	// lookahead, decoded strictly left to right) shouldn't be able to,
	// checked here across every distinct pair rather than one hand picked
	// example.
	inputs := []string{
		"agent:foo",
		"agent.cfoo",
		"agent..cfoo",
		"agent.c.foo",
		"agent::foo",
		"agent.foo",
		"agent..foo",
		".c",
		"c.",
		"..",
		".",
		":",
		"a:.c:b",
	}
	seen := make(map[string]string, len(inputs))
	for _, in := range inputs {
		enc := encodeClientRef(in)
		if prior, dup := seen[enc]; dup {
			t.Fatalf("encodeClientRef(%q) and encodeClientRef(%q) both produced %q", prior, in, enc)
		}
		seen[enc] = in
	}
}

func TestDecodeClientRef_TrailingEscapeCharacter_IsAnError(t *testing.T) {
	if _, err := decodeClientRef("agent."); err == nil {
		t.Fatal("expected an error for a truncated escape sequence")
	}
}

func TestDecodeClientRef_UnrecognizedEscapeSequence_IsAnError(t *testing.T) {
	if _, err := decodeClientRef("agent.x"); err == nil {
		t.Fatal("expected an error for an escape character followed by something that isn't a recognized escape")
	}
}

func TestWriteGrants_AgentRefWithColon_EncodesItForTessera(t *testing.T) {
	var sawClientRef string
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			if r.URL.Path != "/clients/agent.cbilling-reconciler" {
				t.Fatalf("expected the GET path to carry the encoded ref, got %s", r.URL.Path)
			}
			writeJSON(w, http.StatusNotFound, getClientResultWire{Outcome: "not_found"})
			return
		}
		var body onboardRequestBody
		_ = json.NewDecoder(r.Body).Decode(&body)
		sawClientRef = body.ClientRef
		writeJSON(w, http.StatusOK, onboardResultWire{Success: true})
	})

	if err := c.WriteGrants(context.Background(), "agent:billing-reconciler", []Grant{GrantForAPIGroup("orders")}); err != nil {
		t.Fatalf("WriteGrants: %v", err)
	}
	if sawClientRef != "agent.cbilling-reconciler" {
		t.Fatalf("expected the onboard body's client_ref to be the encoded form, got %q", sawClientRef)
	}
}

func TestKill_AgentRefWithColon_ReturnsTheOriginalAgentRefNotTesserasEcho(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/clients/agent.cBilling-Reconciler/kill" {
			t.Fatalf("expected the kill path to carry the encoded ref, got %s", r.URL.Path)
		}
		// Tessera both lowercases and would echo the encoded form back,
		// not the original mixed-form agentRef, this is deliberately not
		// what the caller passed in, to prove Kill doesn't just forward it.
		writeJSON(w, http.StatusOK, killResultWire{Success: true, ClientRef: "agent.cbilling-reconciler", TuplesDeleted: 1})
	})

	result, err := c.Kill(context.Background(), "agent:Billing-Reconciler", "INC-1", "alice")
	if err != nil {
		t.Fatalf("Kill: %v", err)
	}
	if result.AgentRef != "agent:Billing-Reconciler" {
		t.Fatalf("expected KillResult.AgentRef to be the exact original agentRef, got %q", result.AgentRef)
	}
}

// --- test helpers ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// subjectFromAuthHeader decodes the bearer token's payload without
// verifying the signature, this is a test helper reading what the client
// sent, not a stand-in for Hs256JwtValidator, real signature verification
// of this client's tokens happens in the cross-language smoke test that
// spawns the actual Tessera.Service process.
func subjectFromAuthHeader(t *testing.T, r *http.Request, key []byte) string {
	t.Helper()
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		t.Fatalf("expected a bearer token, got %q", auth)
	}
	tok := strings.TrimPrefix(auth, "Bearer ")
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("expected a three part JWT, got %q", tok)
	}
	payloadJSON, err := base64URLDecode(parts[1])
	if err != nil {
		t.Fatalf("decoding token payload: %v", err)
	}
	var payload jwtPayload
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		t.Fatalf("unmarshaling token payload: %v", err)
	}
	return payload.Sub
}

func base64URLDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}
