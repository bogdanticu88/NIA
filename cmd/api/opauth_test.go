package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bogdanticu88/nia/internal/audit"
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

// newTestServerWithRoles wires a token per role so a test can drive the
// same route as three different callers.
func newTestServerWithRoles(t *testing.T) *server {
	t.Helper()
	return newTestServerWithOpauth(opauth.NewStaticStoreWithOperators(map[string]opauth.Operator{
		"tok-viewer":   {Name: "reader", Roles: []opauth.Role{opauth.RoleViewer}},
		"tok-operator": {Name: "day-to-day", Roles: []opauth.Role{opauth.RoleOperator}},
		"tok-admin":    {Name: "bogdan", Roles: []opauth.Role{opauth.RoleAdmin}},
	}))
}

func callAs(t *testing.T, s *server, token, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, r)
	return rec
}

func TestAuthorization_ViewerCanReadButNotWrite(t *testing.T) {
	s := newTestServerWithRoles(t)

	if got := callAs(t, s, "tok-viewer", http.MethodGet, "/agents", "").Code; got != http.StatusOK {
		t.Fatalf("GET /agents as viewer = %d, want 200", got)
	}
	if got := callAs(t, s, "tok-viewer", http.MethodPost, "/agents", `{"ref":"agent:x"}`).Code; got != http.StatusForbidden {
		t.Fatalf("POST /agents as viewer = %d, want 403", got)
	}
	if got := callAs(t, s, "tok-viewer", http.MethodPost, "/tools", `{"name":"t"}`).Code; got != http.StatusForbidden {
		t.Fatalf("POST /tools as viewer = %d, want 403", got)
	}
}

// TestAuthorization_OperatorCannotKill is the separation that closes the
// gap this document used to name directly: an authenticated operator
// who should not be able to kill agents could kill agents.
func TestAuthorization_OperatorCannotKill(t *testing.T) {
	s := newTestServerWithRoles(t)

	if got := callAs(t, s, "tok-operator", http.MethodPost, "/agents", `{"ref":"agent:by-operator"}`).Code; got != http.StatusCreated {
		t.Fatalf("POST /agents as operator = %d, want 201", got)
	}
	rec := callAs(t, s, "tok-operator", http.MethodPost, "/policy/kill", `{"agent_ref":"agent:by-operator","incident":"INC-1"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("POST /policy/kill as operator = %d, want 403: %s", rec.Code, rec.Body.String())
	}
	if got := callAs(t, s, "tok-operator", http.MethodPost, "/policy/restore", `{"agent_ref":"agent:by-operator"}`).Code; got != http.StatusForbidden {
		t.Fatalf("POST /policy/restore as operator = %d, want 403", got)
	}
}

func TestAuthorization_AdminCanKill(t *testing.T) {
	s := newTestServerWithRoles(t)
	if got := callAs(t, s, "tok-admin", http.MethodPost, "/agents", `{"ref":"agent:by-admin"}`).Code; got != http.StatusCreated {
		t.Fatalf("POST /agents as admin = %d, want 201", got)
	}
	rec := callAs(t, s, "tok-admin", http.MethodPost, "/policy/kill", `{"agent_ref":"agent:by-admin","incident":"INC-1"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /policy/kill as admin = %d, want 200: %s", rec.Code, rec.Body.String())
	}
}

// TestAuthorization_UnauthenticatedIs401NotForbidden keeps the two
// answers distinct: "I don't know who you are" and "I know exactly who
// you are and you may not do this" are different facts.
func TestAuthorization_UnauthenticatedIs401NotForbidden(t *testing.T) {
	s := newTestServerWithRoles(t)
	if got := callAs(t, s, "", http.MethodPost, "/policy/kill", `{"agent_ref":"agent:x"}`).Code; got != http.StatusUnauthorized {
		t.Fatalf("status = %d with no token, want 401 rather than 403", got)
	}
}

func TestAuthorization_KilledByRecordsTheAuthenticatedAdmin(t *testing.T) {
	s := newTestServerWithRoles(t)
	if got := callAs(t, s, "tok-admin", http.MethodPost, "/agents", `{"ref":"agent:attributed"}`).Code; got != http.StatusCreated {
		t.Fatalf("register = %d", got)
	}
	// The body claims someone else. The audit trail must not believe it.
	if got := callAs(t, s, "tok-admin", http.MethodPost, "/policy/kill",
		`{"agent_ref":"agent:attributed","incident":"INC-9","operator":"someone-else-entirely"}`).Code; got != http.StatusOK {
		t.Fatalf("kill = %d", got)
	}

	events, err := s.auditLog.(*audit.InMemorySink).ForAgent(t.Context(), "agent:attributed")
	if err != nil {
		t.Fatalf("ForAgent: %v", err)
	}
	for _, e := range events {
		if e.Action == "agent.killed" {
			if e.Operator != "bogdan" {
				t.Fatalf("audit Operator = %q, want the authenticated admin", e.Operator)
			}
			return
		}
	}
	t.Fatal("no agent.killed event was written")
}

// TestAuthorization_ReadRoutesStayReadable is a guard against the
// opposite mistake: over-restricting the investigation surface, which
// is exactly what an on-call engineer needs during an incident.
func TestAuthorization_ReadRoutesStayReadable(t *testing.T) {
	s := newTestServerWithRoles(t)
	for _, path := range []string{"/agents", "/tools", "/audit", "/audit/verify"} {
		if got := callAs(t, s, "tok-viewer", http.MethodGet, path, "").Code; got == http.StatusForbidden {
			t.Fatalf("GET %s as viewer = 403, a viewer is meant to be able to investigate", path)
		}
	}
}

func TestAuthorization_HealthAndMetricsNeedNoRole(t *testing.T) {
	s := newTestServerWithRoles(t)
	for _, path := range []string{"/healthz", "/metrics"} {
		if got := callAs(t, s, "", http.MethodGet, path, "").Code; got != http.StatusOK {
			t.Fatalf("GET %s = %d without a token, want 200", path, got)
		}
	}
}
