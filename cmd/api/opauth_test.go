package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bogdanticu88/nia/internal/opauth"
)

// failingOpStore always fails Verify with a non-ErrInvalidToken error,
// the shape needed to prove operatorAuthMiddleware fails closed (500)
// rather than treating a verification-infrastructure outage as an
// invalid token (401), same reasoning cmd/gateway/authn.go's
// credentialResolver applies to a credential store outage.
type failingOpStore struct{}

var errOpStoreDown = errors.New("operator token store unreachable")

func (failingOpStore) Verify(context.Context, string) (opauth.Operator, error) {
	return opauth.Operator{}, errOpStoreDown
}

func TestRoutes_NoOpauthConfigured_RequestsWorkWithNoAuthorizationHeader(t *testing.T) {
	// The default, unconfigured posture: this is the exact behavior
	// every other test in this package already relies on, stated here
	// as its own test so a future change to routes() that accidentally
	// makes auth mandatory by default gets caught immediately rather
	// than as a wall of unrelated test failures elsewhere.
	s := newTestServer()
	if s.opStore != nil {
		t.Fatalf("newTestServer's opStore = %v, want nil for the default test server", s.opStore)
	}
	mux := s.routes()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 with no operator auth configured: %s", rec.Code, rec.Body.String())
	}
}

func newTestServerWithOpauth(store opauth.Store) *server {
	s := newTestServer()
	s.opStore = store
	return s
}

func TestRoutes_OpauthConfigured_MissingAuthorizationHeaderIsRejected(t *testing.T) {
	s := newTestServerWithOpauth(opauth.NewStaticStore(map[string]string{"tok-bogdan": "bogdan"}))
	mux := s.routes()

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/agents", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for a request with no Authorization header: %s", rec.Code, rec.Body.String())
	}
}

func TestRoutes_OpauthConfigured_WrongSchemeIsRejected(t *testing.T) {
	s := newTestServerWithOpauth(opauth.NewStaticStore(map[string]string{"tok-bogdan": "bogdan"}))
	mux := s.routes()

	req := httptest.NewRequest(http.MethodGet, "/agents", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for a non-Bearer scheme: %s", rec.Code, rec.Body.String())
	}
}

func TestRoutes_OpauthConfigured_InvalidTokenIsRejected(t *testing.T) {
	s := newTestServerWithOpauth(opauth.NewStaticStore(map[string]string{"tok-bogdan": "bogdan"}))
	mux := s.routes()

	req := httptest.NewRequest(http.MethodGet, "/agents", nil)
	req.Header.Set("Authorization", "Bearer tok-not-a-real-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for an unknown token: %s", rec.Code, rec.Body.String())
	}
}

func TestRoutes_OpauthConfigured_ValidTokenIsAccepted(t *testing.T) {
	s := newTestServerWithOpauth(opauth.NewStaticStore(map[string]string{"tok-bogdan": "bogdan"}))
	mux := s.routes()

	req := httptest.NewRequest(http.MethodGet, "/agents", nil)
	req.Header.Set("Authorization", "Bearer tok-bogdan")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for a valid token: %s", rec.Code, rec.Body.String())
	}
}

func TestRoutes_OpauthConfigured_HealthAndMetricsStayReachableWithoutAToken(t *testing.T) {
	s := newTestServerWithOpauth(opauth.NewStaticStore(map[string]string{"tok-bogdan": "bogdan"}))
	mux := s.routes()

	for _, path := range []string{"/healthz", "/metrics"} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s status = %d, want 200 even with operator auth configured, a health check or scraper shouldn't need a token: %s", path, rec.Code, rec.Body.String())
		}
	}
}

func TestRoutes_OpauthConfigured_StoreFailureFailsClosedNot401(t *testing.T) {
	s := newTestServerWithOpauth(failingOpStore{})
	mux := s.routes()

	req := httptest.NewRequest(http.MethodGet, "/agents", nil)
	req.Header.Set("Authorization", "Bearer whatever")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: a token store outage is not the same outcome as an invalid token and must not collapse to the same 401: %s", rec.Code, rec.Body.String())
	}
}

// TestHandleKill_AuthenticatedOperatorOverridesTheClaimedOneInTheAuditTrail
// is the actual security property opauth exists for: with operator
// auth configured, a caller cannot put whatever name it wants in the
// request body and have that show up as who did it, the audit trail
// reflects who the token actually belongs to.
func TestHandleKill_AuthenticatedOperatorOverridesTheClaimedOneInTheAuditTrail(t *testing.T) {
	s := newTestServerWithOpauth(opauth.NewStaticStore(map[string]string{"tok-bogdan": "bogdan"}))
	mux := s.routes()

	authed := func(method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer tok-bogdan")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}

	authed(http.MethodPost, "/agents", `{"ref":"agent:billing","owner":"bogdan"}`)

	killReq := `{"agent_ref":"agent:billing","incident":"INC-001","operator":"someone-else-entirely"}`
	rec := authed(http.MethodPost, "/policy/kill", killReq)
	if rec.Code != http.StatusOK {
		t.Fatalf("kill status = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	rec = authed(http.MethodGet, "/agents/agent:billing/audit", "")
	events := decodeEvents(t, rec)
	killed := events[len(events)-1]
	if killed.Action != "agent.killed" {
		t.Fatalf("got %+v, want the last event to be agent.killed", killed)
	}
	if killed.Operator != "bogdan" {
		t.Fatalf("Operator = %q, want bogdan (the authenticated token holder), the request body's claimed operator (%q) must not win when auth is configured", killed.Operator, "someone-else-entirely")
	}
}
