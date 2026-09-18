package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bogdanticu88/nia/internal/monitoring"
	"github.com/bogdanticu88/nia/internal/opauth"
	"github.com/bogdanticu88/nia/internal/policy"
)

// newTestGatewayWithOpauth is newTestGatewayWithMonitoring plus a
// configured operator token store, so the three read endpoints actually
// have something to return and something to authenticate against.
// Monitoring is on because handleRisk reports "not configured" without
// it, and a 200 that only says "nothing here" would make an
// authentication test pass for the wrong reason.
func newTestGatewayWithOpauth(t *testing.T, tokens map[string]string) *gateway {
	t.Helper()
	g, _ := newTestGatewayWithMonitoring(
		policy.NewInMemoryClient(),
		fakeScorer{value: 1},
		monitoring.Threshold{FlagAt: 1, RevokeAt: 50, KillAt: 100},
	)
	g.opStore = opauth.NewStaticStore(tokens)
	return g
}

// operatorReadPaths is every endpoint on this gateway that answers with
// another agent's security state. Before operator authentication was
// wired in, all three were served to anyone who could reach the port,
// while the tool-call path right next to them demanded a verified
// credential.
var operatorReadPaths = []string{
	"/incidents",
	"/incidents/some-id",
	"/risk/agent:billing",
}

func TestRoutes_OperatorReadEndpoints_RejectAnUnauthenticatedRequest(t *testing.T) {
	g := newTestGatewayWithOpauth(t, map[string]string{"tok-bogdan": "bogdan"})
	routes := g.routes()

	for _, path := range operatorReadPaths {
		rec := httptest.NewRecorder()
		routes.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("GET %s status = %d, want 401 with no Authorization header: %s", path, rec.Code, rec.Body.String())
		}
	}
}

func TestRoutes_OperatorReadEndpoints_RejectAnInvalidToken(t *testing.T) {
	g := newTestGatewayWithOpauth(t, map[string]string{"tok-bogdan": "bogdan"})
	routes := g.routes()

	for _, path := range operatorReadPaths {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer tok-wrong")
		rec := httptest.NewRecorder()
		routes.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("GET %s status = %d, want 401 for an unknown token: %s", path, rec.Code, rec.Body.String())
		}
	}
}

func TestRoutes_OperatorReadEndpoints_RejectAWrongScheme(t *testing.T) {
	g := newTestGatewayWithOpauth(t, map[string]string{"tok-bogdan": "bogdan"})
	req := httptest.NewRequest(http.MethodGet, "/incidents", nil)
	// An agent credential is "<id>.<secret>" presented as a bearer token
	// to the tool-call path. It is not an operator token and must not be
	// accepted here, but the shape worth testing is the cruder one: a
	// scheme that isn't Bearer at all.
	req.Header.Set("Authorization", "Basic dG9rLWJvZ2Rhbjo=")
	rec := httptest.NewRecorder()
	g.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for a non-Bearer scheme: %s", rec.Code, rec.Body.String())
	}
}

func TestRoutes_OperatorReadEndpoints_AcceptAValidToken(t *testing.T) {
	g := newTestGatewayWithOpauth(t, map[string]string{"tok-bogdan": "bogdan"})
	routes := g.routes()

	for _, path := range operatorReadPaths {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer tok-bogdan")
		rec := httptest.NewRecorder()
		routes.ServeHTTP(rec, req)
		// /incidents/some-id is a 404 (no such incident), the other two
		// are 200. Either way the point is that the request got past
		// authentication to the handler instead of being rejected.
		if rec.Code == http.StatusUnauthorized {
			t.Fatalf("GET %s was rejected with 401 despite a valid operator token: %s", path, rec.Body.String())
		}
	}
}

// TestRoutes_HealthAndMetricsStayReachableWithoutAToken keeps the
// operator-auth wrap off the two endpoints a load balancer and a
// Prometheus scraper need, neither of which reveals anything about a
// specific agent.
func TestRoutes_HealthAndMetricsStayReachableWithoutAToken(t *testing.T) {
	g := newTestGatewayWithOpauth(t, map[string]string{"tok-bogdan": "bogdan"})
	routes := g.routes()

	for _, path := range []string{"/healthz", "/metrics"} {
		rec := httptest.NewRecorder()
		routes.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s status = %d, want 200 with no operator token: %s", path, rec.Code, rec.Body.String())
		}
	}
}

// TestRoutes_ToolCallPathIsNotGatedOnAnOperatorToken is the other half
// of the boundary: an agent calling a tool presents its own credential,
// never an operator token, so wrapping the read endpoints must not have
// changed how POST /tools/{tool}/call authenticates. This gateway uses
// headerResolver (the test default), so an agent ref alone is enough
// here, and the absence of any operator token must not turn it into a
// 401.
func TestRoutes_ToolCallPathIsNotGatedOnAnOperatorToken(t *testing.T) {
	g := newTestGatewayWithOpauth(t, map[string]string{"tok-bogdan": "bogdan"})

	req := httptest.NewRequest(http.MethodPost, "/tools/invoice.read/call", strings.NewReader("{}"))
	req.Header.Set("X-Agent-Ref", "agent:billing")
	rec := httptest.NewRecorder()
	g.routes().ServeHTTP(rec, req)

	if rec.Code == http.StatusUnauthorized {
		t.Fatalf("the tool-call path returned 401 with no operator token, it authenticates agents with their own credentials: %s", rec.Body.String())
	}
	// No grant was written for this agent, so the expected outcome is a
	// policy denial, which is proof the request reached the handler.
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (reached the policy check and was denied): %s", rec.Code, rec.Body.String())
	}
}

// TestRoutes_NilOpStore_ServesReadEndpointsUnwrapped documents the
// explicit opt out: NIA_ALLOW_UNAUTHENTICATED=1 is the only way main
// produces a nil opStore (opauth.FromEnvEnforced refuses otherwise),
// and in that case these endpoints are served open on purpose. Every
// other test in this package constructs a gateway with a nil opStore,
// so this is also what keeps them meaningful.
func TestRoutes_NilOpStore_ServesReadEndpointsUnwrapped(t *testing.T) {
	g, _ := newTestGatewayWithMonitoring(
		policy.NewInMemoryClient(),
		fakeScorer{value: 1},
		monitoring.Threshold{FlagAt: 1, RevokeAt: 50, KillAt: 100},
	)
	if g.opStore != nil {
		t.Fatal("opStore is not nil on a directly constructed test gateway")
	}

	rec := httptest.NewRecorder()
	g.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/incidents", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 when running unauthenticated on purpose: %s", rec.Code, rec.Body.String())
	}
}
