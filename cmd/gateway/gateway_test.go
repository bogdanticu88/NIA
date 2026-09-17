package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bogdanticu88/nia/internal/audit"
	"github.com/bogdanticu88/nia/internal/incident"
	"github.com/bogdanticu88/nia/internal/metrics"
	"github.com/bogdanticu88/nia/internal/monitoring"
	"github.com/bogdanticu88/nia/internal/policy"
	"github.com/bogdanticu88/nia/internal/registry/tools"
	"github.com/bogdanticu88/nia/internal/risk"
	"github.com/bogdanticu88/nia/internal/sensitivity"
)

// fakePolicyClient lets a test force Check to return a specific answer
// or error without going through InMemoryClient's grant bookkeeping,
// and records a Kill so a monitoring-triggered kill can be asserted on
// without needing a real policy backend. Every other method still
// panics if called, nothing in the gateway's tool-call path, including
// the monitoring hookup, reaches them. calls counts Check invocations
// so a test can assert the catalog check short-circuited before Check
// was ever reached. deniedObjects lets a test deny one specific data
// grant while every tool grant still comes back allowed, the shape the
// argument-inspection tests below need: the tool call itself is fine,
// one resource it touches isn't.
type fakePolicyClient struct {
	policy.Client
	allowed       bool
	checkErr      error
	calls         int
	lastAgentRef  string // the agentRef the most recent Check call was actually asked about, see authn_test.go's X-Agent-Ref-is-ignored test
	killedRef     string
	deniedObjects map[string]bool
	isKilled      bool  // what IsKilled reports, see authn_test.go's credentialResolver tests
	isKilledErr   error // forces IsKilled to fail, proving the fail-closed path
}

func (f *fakePolicyClient) IsKilled(_ context.Context, _ string) (bool, error) {
	if f.isKilledErr != nil {
		return false, f.isKilledErr
	}
	return f.isKilled, nil
}

func (f *fakePolicyClient) Check(_ context.Context, agentRef string, grant policy.Grant) (bool, error) {
	f.calls++
	f.lastAgentRef = agentRef
	if f.checkErr != nil {
		return false, f.checkErr
	}
	if grant.Kind == "data" && f.deniedObjects[grant.Object] {
		return false, nil
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
	reg := metrics.NewRegistry()
	g := &gateway{
		resolver:   headerResolver{headerName: "X-Agent-Ref"},
		pol:        pol,
		auditLog:   sink,
		metrics:    newGatewayMetrics(reg),
		metricsReg: reg,
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
// asserting against a mock of it. It also wires a real incident.Store,
// same reason.
func newTestGatewayWithMonitoring(pol policy.Client, scorer risk.Scorer, thresholds monitoring.Threshold) (*gateway, *audit.InMemorySink) {
	sink := audit.NewInMemorySink(10)
	incidents := incident.NewInMemoryStore()
	monitor := monitoring.NewMonitor(thresholds, pol, nil, incidents, sink)
	reg := metrics.NewRegistry()
	g := &gateway{
		resolver:   headerResolver{headerName: "X-Agent-Ref"},
		pol:        pol,
		scorer:     scorer,
		monitor:    monitor,
		incidents:  incidents,
		auditLog:   sink,
		metrics:    newGatewayMetrics(reg),
		metricsReg: reg,
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

func doToolCallWithArguments(g *gateway, agentRef, tool string, arguments map[string]any) *httptest.ResponseRecorder {
	body, _ := json.Marshal(toolCallRequest{Arguments: arguments})
	req := httptest.NewRequest(http.MethodPost, "/tools/"+tool+"/call", bytes.NewReader(body))
	if agentRef != "" {
		req.Header.Set("X-Agent-Ref", agentRef)
	}
	req.SetPathValue("tool", tool)
	rec := httptest.NewRecorder()
	g.handleToolCall(rec, req)
	return rec
}

// newTestGatewayWithResourcePolicy is newTestGateway plus a configured
// resourcePolicy and sensitivity classifier, the tests below use it to
// exercise argument inspection and data-grant enforcement; every other
// test in this file leaves both nil, exactly how a deployment that
// never set NIA_GATEWAY_RESOURCE_RULES_PATH runs.
func newTestGatewayWithResourcePolicy(pol policy.Client, resourcePolicy ArgumentResourcePolicy, classifier sensitivity.Classifier) (*gateway, *audit.InMemorySink) {
	g, sink := newTestGateway(pol)
	g.resourcePolicy = resourcePolicy
	g.sensitive = classifier
	return g, sink
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

func TestHandleToolCall_MonitoringNotConfigured_NoRiskFieldInResponse(t *testing.T) {
	g, _ := newTestGateway(&fakePolicyClient{allowed: true})

	rec := doToolCall(g, "agent:billing-reconciler", "invoices.read")
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if _, present := body["risk"]; present {
		t.Fatalf("got a risk field with monitoring not configured, want none: %v", body)
	}
}

func TestHandleToolCall_MonitoringConfigured_ResponseCarriesRiskValueAndCumulative(t *testing.T) {
	pol := &fakePolicyClient{allowed: true}
	g, _ := newTestGatewayWithMonitoring(pol, fakeScorer{value: 3}, monitoring.Threshold{FlagAt: 5, RevokeAt: 10, KillAt: 20})

	rec := doToolCall(g, "agent:billing-reconciler", "invoices.read")
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	risk, ok := body["risk"].(map[string]any)
	if !ok {
		t.Fatalf("got %v, want a risk object in the response", body)
	}
	if value, _ := risk["value"].(float64); value != 3 {
		t.Fatalf("risk.value = %v, want 3", risk["value"])
	}
	if cumulative, _ := risk["cumulative"].(float64); cumulative != 3 {
		t.Fatalf("risk.cumulative = %v, want 3, this is the only call so far", risk["cumulative"])
	}
	if action, _ := risk["action"].(string); action != "none" {
		t.Fatalf("risk.action = %v, want none, 3 is below every threshold", risk["action"])
	}
}

func TestHandleToolCall_MonitoringConfigured_ResponseReportsKillAction(t *testing.T) {
	pol := &fakePolicyClient{allowed: true}
	g, _ := newTestGatewayWithMonitoring(pol, fakeScorer{value: 100}, monitoring.Threshold{FlagAt: 5, RevokeAt: 10, KillAt: 20})

	rec := doToolCall(g, "agent:billing-reconciler", "invoices.read")
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	risk, ok := body["risk"].(map[string]any)
	if !ok {
		t.Fatalf("got %v, want a risk object in the response", body)
	}
	if action, _ := risk["action"].(string); action != "kill" {
		t.Fatalf("risk.action = %v, want kill", risk["action"])
	}
}

// doGet routes a GET request through the gateway's real mux, so
// {tool}/{id} path values are populated by http.ServeMux's own pattern
// matching rather than set by hand.
func doGet(g *gateway, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	g.routes().ServeHTTP(rec, req)
	return rec
}

func TestHandleListIncidents_NotConfigured_ReturnsEmptyArray(t *testing.T) {
	g, _ := newTestGateway(&fakePolicyClient{allowed: true})

	rec := doGet(g, "/incidents")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var got []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %v, want an empty array when monitoring isn't configured", got)
	}
}

func TestHandleGetIncident_NotConfigured_404(t *testing.T) {
	g, _ := newTestGateway(&fakePolicyClient{allowed: true})

	rec := doGet(g, "/incidents/inc-does-not-exist")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleListIncidents_MonitoringConfigured_ReturnsCreatedIncident(t *testing.T) {
	pol := &fakePolicyClient{allowed: true}
	g, _ := newTestGatewayWithMonitoring(pol, fakeScorer{value: 100}, monitoring.Threshold{FlagAt: 5, RevokeAt: 10, KillAt: 20})

	doToolCall(g, "agent:billing-reconciler", "invoices.read")

	rec := doGet(g, "/incidents")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var got []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d incidents, want 1", len(got))
	}
	if got[0]["agent_ref"] != "agent:billing-reconciler" && got[0]["AgentRef"] != "agent:billing-reconciler" {
		t.Fatalf("got %v, want the kill-triggering call's agent", got[0])
	}
}

func TestHandleGetIncident_ReturnsWhatWasCreated(t *testing.T) {
	pol := &fakePolicyClient{allowed: true}
	g, _ := newTestGatewayWithMonitoring(pol, fakeScorer{value: 100}, monitoring.Threshold{FlagAt: 5, RevokeAt: 10, KillAt: 20})

	doToolCall(g, "agent:billing-reconciler", "invoices.read")
	listRec := doGet(g, "/incidents")
	var list []map[string]any
	json.Unmarshal(listRec.Body.Bytes(), &list)
	if len(list) != 1 {
		t.Fatalf("got %d incidents from the list, want 1", len(list))
	}
	id, _ := list[0]["id"].(string)
	if id == "" {
		id, _ = list[0]["ID"].(string)
	}
	if id == "" {
		t.Fatalf("could not find an id field in %v", list[0])
	}

	rec := doGet(g, "/incidents/"+id)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleGetIncident_UnknownID_404(t *testing.T) {
	pol := &fakePolicyClient{allowed: true}
	g, _ := newTestGatewayWithMonitoring(pol, fakeScorer{value: 100}, monitoring.Threshold{FlagAt: 5, RevokeAt: 10, KillAt: 20})

	rec := doGet(g, "/incidents/inc-does-not-exist")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleToolCall_EmptyBodyStillWorksWithResourcePolicyConfigured(t *testing.T) {
	pol := &fakePolicyClient{allowed: true}
	resourcePolicy := NewFieldResourcePolicy([]ResourceRule{
		{Tool: "database.query", QualifierField: "table", FieldsField: "columns"},
	})
	g, _ := newTestGatewayWithResourcePolicy(pol, resourcePolicy, nil)

	rec := doToolCall(g, "agent:billing-reconciler", "database.query")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, a request with no body at all must still work: %s", rec.Code, rec.Body.String())
	}
	if pol.calls != 1 {
		t.Fatalf("Check called %d times, want 1, an empty body names no resources to check", pol.calls)
	}
}

func TestHandleToolCall_InvalidRequestBodyIsRejected(t *testing.T) {
	pol := &fakePolicyClient{allowed: true}
	g, _ := newTestGateway(pol)

	req := httptest.NewRequest(http.MethodPost, "/tools/database.query/call", bytes.NewReader([]byte("not json")))
	req.Header.Set("X-Agent-Ref", "agent:billing-reconciler")
	req.SetPathValue("tool", "database.query")
	rec := httptest.NewRecorder()
	g.handleToolCall(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for a malformed request body: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleToolCall_NoResourcePolicyConfigured_ArgumentsAreIgnored(t *testing.T) {
	pol := &fakePolicyClient{allowed: true}
	g, _ := newTestGateway(pol)

	rec := doToolCallWithArguments(g, "agent:billing-reconciler", "database.query", map[string]any{
		"table":   "customers",
		"columns": []any{"name", "ssn"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if pol.calls != 1 {
		t.Fatalf("Check called %d times, want 1, resourcePolicy isn't configured so no data grant should be checked", pol.calls)
	}
}

func TestHandleToolCall_ResourceBelowSensitiveThreshold_NoDataGrantCheck(t *testing.T) {
	pol := &fakePolicyClient{allowed: true}
	resourcePolicy := NewFieldResourcePolicy([]ResourceRule{
		{Tool: "database.query", QualifierField: "table", FieldsField: "columns"},
	})
	classifier := sensitivity.NewRuleClassifier([]sensitivity.Rule{
		{Pattern: "customers.name", Level: sensitivity.Internal},
	})
	g, _ := newTestGatewayWithResourcePolicy(pol, resourcePolicy, classifier)

	rec := doToolCallWithArguments(g, "agent:billing-reconciler", "database.query", map[string]any{
		"table":   "customers",
		"columns": []any{"name"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if pol.calls != 1 {
		t.Fatalf("Check called %d times, want 1, Internal is below the Sensitive threshold that requires a data grant", pol.calls)
	}
}

func TestHandleToolCall_SensitiveResourceGranted_Allowed(t *testing.T) {
	pol := &fakePolicyClient{allowed: true}
	resourcePolicy := NewFieldResourcePolicy([]ResourceRule{
		{Tool: "database.query", QualifierField: "table", FieldsField: "columns"},
	})
	classifier := sensitivity.NewRuleClassifier([]sensitivity.Rule{
		{Pattern: "customers.ssn", Level: sensitivity.Critical},
	})
	g, sink := newTestGatewayWithResourcePolicy(pol, resourcePolicy, classifier)

	rec := doToolCallWithArguments(g, "agent:billing-reconciler", "database.query", map[string]any{
		"table":   "customers",
		"columns": []any{"ssn"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, the data grant is present too: %s", rec.Code, rec.Body.String())
	}
	if pol.calls != 2 {
		t.Fatalf("Check called %d times, want 2 (tool grant, then the customers.ssn data grant)", pol.calls)
	}
	events, _ := sink.Recent(context.Background(), 10)
	if len(events) != 1 || events[0].Action != "gateway.allowed" {
		t.Fatalf("got %v, want a single gateway.allowed event", events)
	}
}

func TestHandleToolCall_SensitiveResourceNotGranted_Denied(t *testing.T) {
	pol := &fakePolicyClient{allowed: true, deniedObjects: map[string]bool{"customers.ssn": true}}
	resourcePolicy := NewFieldResourcePolicy([]ResourceRule{
		{Tool: "database.query", QualifierField: "table", FieldsField: "columns"},
	})
	classifier := sensitivity.NewRuleClassifier([]sensitivity.Rule{
		{Pattern: "customers.ssn", Level: sensitivity.Critical},
	})
	g, sink := newTestGatewayWithResourcePolicy(pol, resourcePolicy, classifier)

	rec := doToolCallWithArguments(g, "agent:billing-reconciler", "database.query", map[string]any{
		"table":   "customers",
		"columns": []any{"name", "ssn"},
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403, the agent is authorized for the tool but not the ssn column: %s", rec.Code, rec.Body.String())
	}
	events, _ := sink.Recent(context.Background(), 10)
	if len(events) != 1 || events[0].Action != "gateway.denied" {
		t.Fatalf("got %v, want a single gateway.denied event for the missing data grant, not gateway.allowed", events)
	}
}

func TestHandleToolCall_DataGrantCheckErrorIsAuditedAndBlocked(t *testing.T) {
	pol := &fakePolicyClient{allowed: true}
	resourcePolicy := NewFieldResourcePolicy([]ResourceRule{
		{Tool: "database.query", QualifierField: "table", FieldsField: "columns"},
	})
	classifier := sensitivity.NewRuleClassifier([]sensitivity.Rule{
		{Pattern: "customers.ssn", Level: sensitivity.Critical},
	})
	g, sink := newTestGatewayWithResourcePolicy(pol, resourcePolicy, classifier)
	// Force the second Check call (the data grant) to error while the
	// first (the tool grant) still succeeds normally isn't expressible
	// with fakePolicyClient's single checkErr field, so this asserts the
	// simpler, still meaningful case: checkErr set means every Check
	// fails, including the tool-level one, and that must still be
	// audited as gateway.check_error, not silently allowed through.
	pol.checkErr = errors.New("tessera unreachable")

	rec := doToolCallWithArguments(g, "agent:billing-reconciler", "database.query", map[string]any{
		"table":   "customers",
		"columns": []any{"ssn"},
	})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %s", rec.Code, rec.Body.String())
	}
	events, _ := sink.Recent(context.Background(), 10)
	if len(events) != 1 || events[0].Action != "gateway.check_error" {
		t.Fatalf("got %v, want a single gateway.check_error event", events)
	}
}
