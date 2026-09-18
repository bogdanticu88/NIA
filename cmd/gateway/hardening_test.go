package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bogdanticu88/nia/internal/policy"
	"github.com/bogdanticu88/nia/internal/ratelimit"
	niahttp "github.com/bogdanticu88/nia/internal/transport/http"
)

// allowedGateway is a gateway whose policy client already grants the
// tool, so a refused request is refused by a limiter rather than by
// authorization, which is what these tests need to distinguish.
func allowedGateway(t *testing.T) *gateway {
	t.Helper()
	pol := policy.NewInMemoryClient()
	if err := pol.WriteGrants(t.Context(), "agent:billing", []policy.Grant{policy.GrantForTool("invoice.read")}); err != nil {
		t.Fatalf("WriteGrants: %v", err)
	}
	g, _ := newTestGateway(pol)
	return g
}

func toolCall(t *testing.T, g *gateway, agentRef, addr string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/tools/invoice.read/call", strings.NewReader("{}"))
	req.Header.Set("X-Agent-Ref", agentRef)
	req.RemoteAddr = addr
	rec := httptest.NewRecorder()
	g.routes().ServeHTTP(rec, req)
	return rec
}

// TestHandleToolCall_PerAgentRateLimitRefusesABurst is the enforcement
// half of what internal/risk's call_rate signal only detects. The signal
// scores a burst and feeds containment; this refuses it outright.
func TestHandleToolCall_PerAgentRateLimitRefusesABurst(t *testing.T) {
	g := allowedGateway(t)
	g.agentLimiter = ratelimit.New(1, 3)

	for i := 0; i < 3; i++ {
		if got := toolCall(t, g, "agent:billing", "203.0.113.7:1").Code; got == http.StatusTooManyRequests {
			t.Fatalf("call %d inside the burst was refused", i+1)
		}
	}
	rec := toolCall(t, g, "agent:billing", "203.0.113.7:1")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d past the burst, want 429: %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("no Retry-After header on the 429")
	}
}

// TestHandleToolCall_PerAgentLimitFollowsTheAgentNotTheAddress is why
// the per-agent limiter exists alongside the per-client one: an agent
// spreading its flood across many source addresses defeats an
// address-keyed limit entirely.
func TestHandleToolCall_PerAgentLimitFollowsTheAgentNotTheAddress(t *testing.T) {
	g := allowedGateway(t)
	g.agentLimiter = ratelimit.New(1, 2)

	toolCall(t, g, "agent:billing", "203.0.113.1:1")
	toolCall(t, g, "agent:billing", "203.0.113.2:1")
	rec := toolCall(t, g, "agent:billing", "203.0.113.3:1")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d from a third address, want 429: one agent is one bucket no matter where it calls from", rec.Code)
	}
}

func TestHandleToolCall_PerAgentLimitIsPerAgent(t *testing.T) {
	pol := policy.NewInMemoryClient()
	for _, ref := range []string{"agent:billing", "agent:payroll"} {
		if err := pol.WriteGrants(t.Context(), ref, []policy.Grant{policy.GrantForTool("invoice.read")}); err != nil {
			t.Fatalf("WriteGrants(%s): %v", ref, err)
		}
	}
	g, _ := newTestGateway(pol)
	g.agentLimiter = ratelimit.New(1, 1)

	toolCall(t, g, "agent:billing", "203.0.113.7:1")
	if got := toolCall(t, g, "agent:billing", "203.0.113.7:1").Code; got != http.StatusTooManyRequests {
		t.Fatalf("the first agent's second call got %d, want 429", got)
	}
	if got := toolCall(t, g, "agent:payroll", "203.0.113.7:1").Code; got == http.StatusTooManyRequests {
		t.Fatal("a second agent was refused because the first had spent its tokens")
	}
}

// TestHandleToolCall_RateLimitedCallIsAudited keeps a refusal
// investigable. A burst that gets refused is exactly the thing an
// incident review needs to see, and it would otherwise leave no trace at
// all, since the request never reaches the audited decision path.
func TestHandleToolCall_RateLimitedCallIsAudited(t *testing.T) {
	pol := policy.NewInMemoryClient()
	if err := pol.WriteGrants(t.Context(), "agent:billing", []policy.Grant{policy.GrantForTool("invoice.read")}); err != nil {
		t.Fatalf("WriteGrants: %v", err)
	}
	g, sink := newTestGateway(pol)
	g.agentLimiter = ratelimit.New(1, 1)

	toolCall(t, g, "agent:billing", "203.0.113.7:1")
	toolCall(t, g, "agent:billing", "203.0.113.7:1")

	events, err := sink.Recent(t.Context(), 0)
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	var found bool
	for _, e := range events {
		if e.Action == "gateway.rate_limited" && e.AgentRef == "agent:billing" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no gateway.rate_limited event was written, events: %+v", events)
	}
}

// TestHandleToolCall_PerAgentLimitRunsBeforeAuthorization keeps the
// ordering honest: the limit exists to stop work, so it has to come
// before the policy check, the catalog lookup and the scoring, not after
// them.
func TestHandleToolCall_PerAgentLimitRunsBeforeAuthorization(t *testing.T) {
	counting := &countingPolicy{Client: policy.NewInMemoryClient()}
	if err := counting.WriteGrants(t.Context(), "agent:billing", []policy.Grant{policy.GrantForTool("invoice.read")}); err != nil {
		t.Fatalf("WriteGrants: %v", err)
	}
	g, _ := newTestGateway(counting)
	g.agentLimiter = ratelimit.New(1, 1)

	toolCall(t, g, "agent:billing", "203.0.113.7:1")
	before := counting.checks
	toolCall(t, g, "agent:billing", "203.0.113.7:1") // refused
	if counting.checks != before {
		t.Fatalf("policy.Check ran %d extra times on a rate-limited call, the limit must refuse before doing work", counting.checks-before)
	}
}

type countingPolicy struct {
	policy.Client
	checks int
}

func (c *countingPolicy) Check(ctx context.Context, agentRef string, grant policy.Grant) (bool, error) {
	c.checks++
	return c.Client.Check(ctx, agentRef, grant)
}

func TestRoutes_GatewayOversizedBodyIsRefused(t *testing.T) {
	g := allowedGateway(t)
	huge := `{"arguments":{"padding":"` + strings.Repeat("A", int(niahttp.DefaultMaxRequestBytes)+1024) + `"}}`

	req := httptest.NewRequest(http.MethodPost, "/tools/invoice.read/call", strings.NewReader(huge))
	req.Header.Set("X-Agent-Ref", "agent:billing")
	rec := httptest.NewRecorder()
	g.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge && rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 413 or 400 for a body over the cap", rec.Code)
	}
}

func TestRoutes_GatewayClientRateLimitAppliesBeforeIdentityResolution(t *testing.T) {
	g := allowedGateway(t)
	g.clientLimiter = ratelimit.New(1, 1)

	// No X-Agent-Ref at all, so this never resolves an identity. The
	// first is a 401, the second is refused earlier than that.
	call := func() int {
		req := httptest.NewRequest(http.MethodPost, "/tools/invoice.read/call", strings.NewReader("{}"))
		req.RemoteAddr = "203.0.113.7:9999"
		rec := httptest.NewRecorder()
		g.routes().ServeHTTP(rec, req)
		return rec.Code
	}
	if got := call(); got != http.StatusUnauthorized {
		t.Fatalf("first call status = %d, want 401", got)
	}
	if got := call(); got != http.StatusTooManyRequests {
		t.Fatalf("second call status = %d, want 429: an uncredentialed flood must be refused before credential verification", got)
	}
}

func TestRoutes_GatewayHealthIsNeverRateLimited(t *testing.T) {
	g := allowedGateway(t)
	g.clientLimiter = ratelimit.New(1, 1)
	for i := 0; i < 20; i++ {
		req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		req.RemoteAddr = "203.0.113.7:2222"
		rec := httptest.NewRecorder()
		g.routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("health check %d got %d", i, rec.Code)
		}
	}
}

func TestHandleToolCall_NilLimitersAreDisabled(t *testing.T) {
	g := allowedGateway(t)
	if g.agentLimiter != nil || g.clientLimiter != nil {
		t.Fatal("this test is checking the nil case, but the test gateway has limiters")
	}
	for i := 0; i < 100; i++ {
		if got := toolCall(t, g, "agent:billing", "203.0.113.7:1").Code; got == http.StatusTooManyRequests {
			t.Fatalf("call %d refused with nil limiters", i)
		}
	}
}
