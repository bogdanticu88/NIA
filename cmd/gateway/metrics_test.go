package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bogdanticu88/nia/internal/monitoring"
	"github.com/bogdanticu88/nia/internal/sensitivity"
)

// This file proves the metrics wired into cmd/gateway's handlers move
// the way cmd/api/metrics_test.go proves it for the control plane:
// one counter per outcome, driven through the real HTTP path, read
// back through gatewayMetrics rather than by parsing scraped text.

func TestMetrics_ToolCall_CountsAllowed(t *testing.T) {
	pol := &fakePolicyClient{allowed: true}
	g, _ := newTestGatewayWithCatalog(pol, fakeToolReader{found: true})

	doToolCall(g, "agent:billing-reconciler", "invoices.read")
	if got := g.metrics.requests.Value("allowed"); got != 1 {
		t.Fatalf("allowed = %d, want 1", got)
	}
}

func TestMetrics_ToolCall_CountsDeniedTool(t *testing.T) {
	g, _ := newTestGateway(&fakePolicyClient{allowed: false})

	doToolCall(g, "agent:billing-reconciler", "invoices.read")
	if got := g.metrics.requests.Value("denied_tool"); got != 1 {
		t.Fatalf("denied_tool = %d, want 1", got)
	}
}

func TestMetrics_ToolCall_CountsCheckError(t *testing.T) {
	g, _ := newTestGateway(&fakePolicyClient{checkErr: errors.New("openfga unreachable")})

	doToolCall(g, "agent:billing-reconciler", "invoices.read")
	if got := g.metrics.requests.Value("check_error"); got != 1 {
		t.Fatalf("check_error = %d, want 1", got)
	}
}

func TestMetrics_ToolCall_CountsUnresolved(t *testing.T) {
	g, _ := newTestGateway(&fakePolicyClient{allowed: true})

	doToolCall(g, "", "invoices.read")
	if got := g.metrics.requests.Value("unresolved"); got != 1 {
		t.Fatalf("unresolved = %d, want 1", got)
	}
}

func TestMetrics_ToolCall_CountsUnknownToolAndLookupError(t *testing.T) {
	pol := &fakePolicyClient{allowed: true}
	g, _ := newTestGatewayWithCatalog(pol, fakeToolReader{found: false})
	doToolCall(g, "agent:billing-reconciler", "not-a-real-tool")
	if got := g.metrics.requests.Value("unknown_tool"); got != 1 {
		t.Fatalf("unknown_tool = %d, want 1", got)
	}

	g2, _ := newTestGatewayWithCatalog(pol, fakeToolReader{lookupErr: errors.New("cmd/api unreachable")})
	doToolCall(g2, "agent:billing-reconciler", "invoices.read")
	if got := g2.metrics.requests.Value("tool_lookup_error"); got != 1 {
		t.Fatalf("tool_lookup_error = %d, want 1", got)
	}
}

func TestMetrics_ToolCall_CountsDeniedResource(t *testing.T) {
	pol := &fakePolicyClient{allowed: true, deniedObjects: map[string]bool{"customers.ssn": true}}
	resourcePolicy := NewFieldResourcePolicy([]ResourceRule{
		{Tool: "database.query", QualifierField: "table", FieldsField: "columns"},
	})
	classifier := sensitivity.NewRuleClassifier([]sensitivity.Rule{
		{Pattern: "customers.ssn", Level: sensitivity.Critical},
	})
	g, _ := newTestGatewayWithResourcePolicy(pol, resourcePolicy, classifier)

	doToolCallWithArguments(g, "agent:billing-reconciler", "database.query", map[string]any{
		"table":   "customers",
		"columns": []any{"name", "ssn"},
	})
	if got := g.metrics.requests.Value("denied_resource"); got != 1 {
		t.Fatalf("denied_resource = %d, want 1", got)
	}
}

func TestMetrics_MonitoringActions_CountsKillAndFlagButNotNone(t *testing.T) {
	pol := &fakePolicyClient{allowed: true}
	g, _ := newTestGatewayWithMonitoring(pol, fakeScorer{value: 100}, monitoring.Threshold{FlagAt: 5, RevokeAt: 10, KillAt: 20})
	doToolCall(g, "agent:billing-reconciler", "invoices.read")
	if got := g.metrics.monitoringActions.Value("kill"); got != 1 {
		t.Fatalf("kill = %d, want 1", got)
	}

	g2, _ := newTestGatewayWithMonitoring(&fakePolicyClient{allowed: true}, fakeScorer{value: 5}, monitoring.Threshold{FlagAt: 5, RevokeAt: 10, KillAt: 20})
	doToolCall(g2, "agent:billing-reconciler", "invoices.read")
	if got := g2.metrics.monitoringActions.Value("flag"); got != 1 {
		t.Fatalf("flag = %d, want 1", got)
	}

	g3, _ := newTestGatewayWithMonitoring(&fakePolicyClient{allowed: true}, fakeScorer{value: 0}, monitoring.Threshold{FlagAt: 5, RevokeAt: 10, KillAt: 20})
	doToolCall(g3, "agent:billing-reconciler", "invoices.read")
	if got := g3.metrics.monitoringActions.Value("none"); got != 0 {
		t.Fatalf("none = %d, want 0, ActionNone is deliberately not counted", got)
	}
}

func TestMetrics_ServeHTTP_ServesRegisteredCounters(t *testing.T) {
	g, _ := newTestGateway(&fakePolicyClient{allowed: true})
	doToolCall(g, "agent:billing-reconciler", "invoices.read")

	rec := httptest.NewRecorder()
	g.metricsReg.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	out := rec.Body.String()
	if !strings.Contains(out, `nia_gateway_requests_total{outcome="allowed"} 1`) {
		t.Fatalf("output missing the allowed counter line: %s", out)
	}
}

func TestHandleRisk_NotConfigured_ReportsUnconfigured(t *testing.T) {
	g, _ := newTestGateway(&fakePolicyClient{allowed: true})

	rec := doGet(g, "/risk/agent:billing-reconciler")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"configured":false`) {
		t.Fatalf("body = %s, want configured:false when monitoring is not set up", rec.Body.String())
	}
}

func TestHandleRisk_Configured_ReportsCumulativeThresholdsAndIncidents(t *testing.T) {
	pol := &fakePolicyClient{allowed: true}
	g, _ := newTestGatewayWithMonitoring(pol, fakeScorer{value: 5}, monitoring.Threshold{FlagAt: 5, RevokeAt: 10, KillAt: 20})
	doToolCall(g, "agent:billing-reconciler", "invoices.read")

	rec := doGet(g, "/risk/agent:billing-reconciler")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"configured":true`) {
		t.Fatalf("body = %s, want configured:true", body)
	}
	if !strings.Contains(body, `"cumulative":5`) {
		t.Fatalf("body = %s, want cumulative:5", body)
	}
	if !strings.Contains(body, `"incidents"`) {
		t.Fatalf("body = %s, want an incidents field with the flag this call created", body)
	}
}

func TestHandleRisk_MissingRef_400(t *testing.T) {
	g, _ := newTestGateway(&fakePolicyClient{allowed: true})

	req := httptest.NewRequest(http.MethodGet, "/risk/", nil)
	rec := httptest.NewRecorder()
	g.handleRisk(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for a missing ref", rec.Code)
	}
}
