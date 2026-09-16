package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bogdanticu88/nia/internal/audit"
	"github.com/bogdanticu88/nia/internal/monitoring"
	"github.com/bogdanticu88/nia/internal/policy"
	"github.com/bogdanticu88/nia/internal/registry/tools"
	"github.com/bogdanticu88/nia/internal/risk"
)

// fakePolicyClient lets a test force Check to return a specific answer
// or error without going through InMemoryClient's grant bookkeeping,
// and records a Kill so a monitoring-triggered kill can be asserted on
// without needing a real policy backend. Every other method still
// panics if called, nothing in the gateway's tool-call path, including
// the monitoring hookup, reaches them. calls counts Check invocations
// so a test can assert the catalog check short-circuited before Check
// was ever reached.
type fakePolicyClient struct {
	policy.Client
	allowed   bool
	checkErr  error
	calls     int
	killedRef string
}

func (f *fakePolicyClient) Check(context.Context, string, policy.Grant) (bool, error) {
	f.calls++
	if f.checkErr != nil {
		return false, f.checkErr
	}
	return f.allowed, nil
}

func (f *fakePolicyClient) Kill(_ context.Context, agentRef, _, _ string) (policy.KillResult, error) {
	f.killedRef = agentRef
	return policy.KillResult{AgentRef: agentRef}, nil
}

// fakeToolReader lets a test force a catalog lookup to succeed, come
// back not-found, or error, without a real cmd/api to talk to.
type fakeToolReader struct {
	found     bool
	lookupErr error
}

func (f fakeToolReader) Get(_ context.Context, name string) (tools.Tool, error) {
	if f.lookupErr != nil {
		return tools.Tool{}, f.lookupErr
	}
	if !f.found {
		return tools.Tool{}, tools.ErrNotFound
	}
	return tools.Tool{Name: name}, nil
}

func newTestGateway(pol policy.Client) (*gateway, *audit.InMemorySink) {
	sink := audit.NewInMemorySink(10)
	g := &gateway{
		resolver: headerResolver{headerName: "X-Agent-Ref"},
		pol:      pol,
		auditLog: sink,
	}
	return g, sink
}

// newTestGatewayWithCatalog is newTestGateway plus a configured
// toolCat, the tests below use it to exercise the catalog-enforcement
// path; every other test in this file leaves toolCat nil, which is
// exactly how a deployment that never set NIA_TOOLS_API_URL runs.
func newTestGatewayWithCatalog(pol policy.Client, toolCat tools.Reader) (*gateway, *audit.InMemorySink) {
	g, sink := newTestGateway(pol)
	g.toolCat = toolCat
	return g, sink
}

// fakeScorer returns a fixed score for every call, so a test can put an
// allowed call on either side of a monitoring threshold deterministically.
type fakeScorer struct {
	value float64
}

func (f fakeScorer) Score(_ context.Context, call risk.CallContext) (risk.Score, error) {
	return risk.Score{AgentRef: call.AgentRef, Value: f.value, ScoredAt: time.Now()}, nil
}

// newTestGatewayWithMonitoring wires a real monitoring.Monitor (not a
// fake) sharing the gateway's own audit sink, the same way main() wires
// them, so these tests exercise the real handoff between the gateway's
// scoring step and internal/monitoring's own decision logic rather than
// asserting against a mock of it.
func newTestGatewayWithMonitoring(pol policy.Client, scorer risk.Scorer, thresholds monitoring.Threshold) (*gateway, *audit.InMemorySink) {
	sink := audit.NewInMemorySink(10)
	monitor := monitoring.NewMonitor(thresholds, pol, nil, sink)
	g := &gateway{
		resolver: headerResolver{headerName: "X-Agent-Ref"},
		pol:      pol,
		scorer:   scorer,
		monitor:  monitor,
		auditLog: sink,
	}
	return g, sink
}

func doToolCall(g *gateway, agentRef, tool string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/tools/"+tool+"/call", nil)
	if agentRef != "" {
		req.Header.Set("X-Agent-Ref", agentRef)
	}
	req.SetPathValue("tool", tool)
	rec := httptest.NewRecorder()
	g.handleToolCall(rec, req)
	return rec
}

func TestHandleToolCall_AllowedIsAudited(t *testing.T) {
	g, sink := newTestGateway(&fakePolicyClient{allowed: true})

	rec := doToolCall(g, "agent:billing-reconciler", "invoices.read")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	events, err := sink.Recent(context.Background(), 10)
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("got %d audit events, want 1: %v", len(events), events)
	}
	if events[0].Action != "gateway.allowed" {
		t.Fatalf("Action = %q, want gateway.allowed", events[0].Action)
	}
	if events[0].AgentRef != "agent:billing-reconciler" {
		t.Fatalf("AgentRef = %q, want agent:billing-reconciler", events[0].AgentRef)
	}
}

func TestHandleToolCall_DeniedIsAudited(t *testing.T) {
	g, sink := newTestGateway(&fakePolicyClient{allowed: false})

	rec := doToolCall(g, "agent:billing-reconciler", "invoices.delete")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: %s", rec.Code, rec.Body.String())
	}

	events, _ := sink.Recent(context.Background(), 10)
	if len(events) != 1 || events[0].Action != "gateway.denied" {
		t.Fatalf("got %v, want exactly one gateway.denied event", events)
	}
}

func TestHandleToolCall_CheckErrorIsAudited(t *testing.T) {
	g, sink := newTestGateway(&fakePolicyClient{checkErr: errors.New("openfga unreachable")})

	rec := doToolCall(g, "agent:billing-reconciler", "invoices.read")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %s", rec.Code, rec.Body.String())
	}

	events, _ := sink.Recent(context.Background(), 10)
	if len(events) != 1 || events[0].Action != "gateway.check_error" {
		t.Fatalf("got %v, want exactly one gateway.check_error event", events)
	}
}

func TestHandleToolCall_UnresolvedIdentityIsNotAudited(t *testing.T) {
	// No X-Agent-Ref header means resolution fails before Check is ever
	// called. There's no subject to attach an event to, so nothing
	// should land in the trail, unlike a denial, this never became a
	// decision about an agent.
	g, sink := newTestGateway(&fakePolicyClient{allowed: true})

	rec := doToolCall(g, "", "invoices.read")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401: %s", rec.Code, rec.Body.String())
	}

	events, _ := sink.Recent(context.Background(), 10)
	if len(events) != 0 {
		t.Fatalf("got %d audit events for an unresolved caller, want 0: %v", len(events), events)
	}
}

func TestHandleToolCall_UnknownToolRejectedWhenCatalogConfigured(t *testing.T) {
	pol := &fakePolicyClient{allowed: true}
	g, sink := newTestGatewayWithCatalog(pol, fakeToolReader{found: false})

	rec := doToolCall(g, "agent:billing-reconciler", "not-a-real-tool")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404: %s", rec.Code, rec.Body.String())
	}
	if pol.calls != 0 {
		t.Fatalf("policy Check was called %d times, want 0, an unregistered tool should never reach it", pol.calls)
	}

	events, _ := sink.Recent(context.Background(), 10)
	if len(events) != 1 || events[0].Action != "gateway.unknown_tool" {
		t.Fatalf("got %v, want exactly one gateway.unknown_tool event", events)
	}
}

func TestHandleToolCall_RegisteredToolProceedsToPolicyCheck(t *testing.T) {
	pol := &fakePolicyClient{allowed: true}
	g, sink := newTestGatewayWithCatalog(pol, fakeToolReader{found: true})

	rec := doToolCall(g, "agent:billing-reconciler", "invoices.read")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if pol.calls != 1 {
		t.Fatalf("policy Check was called %d times, want 1", pol.calls)
	}

	events, _ := sink.Recent(context.Background(), 10)
	if len(events) != 1 || events[0].Action != "gateway.allowed" {
		t.Fatalf("got %v, want exactly one gateway.allowed event", events)
	}
}

func TestHandleToolCall_ToolLookupErrorIsAudited(t *testing.T) {
	pol := &fakePolicyClient{allowed: true}
	g, sink := newTestGatewayWithCatalog(pol, fakeToolReader{lookupErr: errors.New("cmd/api unreachable")})

	rec := doToolCall(g, "agent:billing-reconciler", "invoices.read")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %s", rec.Code, rec.Body.String())
	}
	if pol.calls != 0 {
		t.Fatalf("policy Check was called %d times, want 0, a lookup error should never reach it", pol.calls)
	}

	events, _ := sink.Recent(context.Background(), 10)
	if len(events) != 1 || events[0].Action != "gateway.tool_lookup_error" {
		t.Fatalf("got %v, want exactly one gateway.tool_lookup_error event", events)
	}
}

func TestHandleToolCall_MonitoringNotConfigured_OnlyGatewayAllowedIsAudited(t *testing.T) {
	// The default test gateway (used by every test above this one)
	// leaves scorer and monitor both nil. If g.observe were reached
	// without a monitor nil-check, this would panic on a nil interface
	// call, so this also stands in as a regression guard for that.
	g, sink := newTestGateway(&fakePolicyClient{allowed: true})

	rec := doToolCall(g, "agent:billing-reconciler", "invoices.read")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	events, _ := sink.Recent(context.Background(), 10)
	if len(events) != 1 || events[0].Action != "gateway.allowed" {
		t.Fatalf("got %v, want only gateway.allowed when monitoring isn't configured", events)
	}
}

func TestHandleToolCall_AllowedCallBelowEveryThreshold_NoMonitoringAction(t *testing.T) {
	pol := &fakePolicyClient{allowed: true}
	g, sink := newTestGatewayWithMonitoring(pol, fakeScorer{value: 0}, monitoring.Threshold{FlagAt: 5, RevokeAt: 10, KillAt: 20})

	rec := doToolCall(g, "agent:billing-reconciler", "invoices.read")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	events, _ := sink.Recent(context.Background(), 10)
	if len(events) != 1 || events[0].Action != "gateway.allowed" {
		t.Fatalf("got %v, want only gateway.allowed, the score is below every threshold", events)
	}
}

func TestHandleToolCall_AllowedCallCrossingKillThreshold_TriggersMonitoringKill(t *testing.T) {
	pol := &fakePolicyClient{allowed: true}
	g, sink := newTestGatewayWithMonitoring(pol, fakeScorer{value: 100}, monitoring.Threshold{FlagAt: 5, RevokeAt: 10, KillAt: 20})

	rec := doToolCall(g, "agent:billing-reconciler", "invoices.read")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, the call itself was legitimately allowed: %s", rec.Code, rec.Body.String())
	}
	events, _ := sink.Recent(context.Background(), 10)
	if len(events) != 2 || events[0].Action != "gateway.allowed" || events[1].Action != "monitoring.kill" {
		t.Fatalf("got %v, want gateway.allowed followed by monitoring.kill", events)
	}
	if pol.killedRef != "agent:billing-reconciler" {
		t.Fatalf("policy Kill was called with ref %q, want agent:billing-reconciler", pol.killedRef)
	}
}

func TestHandleToolCall_AllowedCallCrossingFlagThreshold_TriggersMonitoringFlag(t *testing.T) {
	pol := &fakePolicyClient{allowed: true}
	g, sink := newTestGatewayWithMonitoring(pol, fakeScorer{value: 5}, monitoring.Threshold{FlagAt: 5, RevokeAt: 10, KillAt: 20})

	rec := doToolCall(g, "agent:billing-reconciler", "invoices.read")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	events, _ := sink.Recent(context.Background(), 10)
	if len(events) != 2 || events[0].Action != "gateway.allowed" || events[1].Action != "monitoring.flag" {
		t.Fatalf("got %v, want gateway.allowed followed by monitoring.flag", events)
	}
}
