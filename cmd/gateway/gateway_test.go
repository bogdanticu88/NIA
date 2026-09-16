package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bogdanticu88/nia/internal/audit"
	"github.com/bogdanticu88/nia/internal/policy"
	"github.com/bogdanticu88/nia/internal/registry/tools"
)

// fakePolicyClient lets a test force Check to return a specific answer
// or error without going through InMemoryClient's grant bookkeeping.
// Every other method panics if called, the gateway's tool-call path
// never reaches them. calls counts invocations so a test can assert
// the catalog check short-circuited before Check was ever reached.
type fakePolicyClient struct {
	policy.Client
	allowed  bool
	checkErr error
	calls    int
}

func (f *fakePolicyClient) Check(context.Context, string, policy.Grant) (bool, error) {
	f.calls++
	if f.checkErr != nil {
		return false, f.checkErr
	}
	return f.allowed, nil
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
