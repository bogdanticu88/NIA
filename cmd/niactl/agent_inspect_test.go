package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPrintAgentInspection_NotRegistered(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "agent not registered"})
	}))
	defer srv.Close()
	t.Setenv("NIA_API_URL", srv.URL)

	var buf bytes.Buffer
	printAgentInspection(&buf, "agent:ghost", 10)
	out := buf.String()
	if !strings.Contains(out, "agent:ghost is not registered") {
		t.Fatalf("got %q, want a plain not-registered message", out)
	}
	if strings.Contains(out, "credentials:") {
		t.Fatalf("got %q, want nothing past the not-registered message for an agent that doesn't exist", out)
	}
}

func TestPrintAgentInspection_UnreachableAPI(t *testing.T) {
	t.Setenv("NIA_API_URL", "http://127.0.0.1:1")

	var buf bytes.Buffer
	printAgentInspection(&buf, "agent:test", 10)
	if !strings.Contains(buf.String(), "could not reach") {
		t.Fatalf("got %q, want an honest error rather than a panic", buf.String())
	}
}

func TestPrintAgentInspection_FullReport(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /agents/agent:billing-reconciler", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"Ref": "agent:billing-reconciler", "Owner": "bogdan", "BusinessUnit": "finance",
			"Purpose": "reconciles invoices", "Assurance": "medium", "State": "active",
		})
	})
	mux.HandleFunc("GET /agents/agent:billing-reconciler/credentials", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]map[string]any{
			{"ID": "cred-1", "Kind": "api_key", "Status": "active"},
		})
	})
	mux.HandleFunc("GET /agents/agent:billing-reconciler/grants", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]map[string]any{
			{"Kind": "tool", "Object": "invoice-lookup"},
		})
	})
	mux.HandleFunc("GET /agents/agent:billing-reconciler/audit", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]map[string]any{
			{"Action": "agent.registered", "Detail": "", "At": "2026-01-01T00:00:00Z"},
			{"Action": "credential.issued", "Detail": "api_key cred-1", "At": "2026-01-01T00:01:00Z"},
		})
	})
	mux.HandleFunc("GET /graph/agent:billing-reconciler/blast-radius", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"total": 2, "by_kind": map[string]int{"tool": 2}, "severity": "MEDIUM",
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	t.Setenv("NIA_API_URL", srv.URL)

	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"agent_ref": "agent:billing-reconciler", "configured": true,
			"cumulative": 5.0, "thresholds": map[string]any{"FlagAt": 5.0, "RevokeAt": 10.0, "KillAt": 20.0},
		})
	}))
	defer gw.Close()
	t.Setenv("NIA_GATEWAY_URL", gw.URL)

	var buf bytes.Buffer
	printAgentInspection(&buf, "agent:billing-reconciler", 10)
	out := buf.String()

	for _, want := range []string{
		"agent: agent:billing-reconciler",
		"owner: bogdan",
		"business unit: finance",
		"state: active",
		"cred-1", "api_key", "active",
		"tool:invoice-lookup",
		"credential.issued: api_key cred-1",
		"2 node(s) reachable, severity MEDIUM",
		"cumulative risk: 5",
		"flag at 5, revoke at 10, kill at 20",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("report missing %q, got:\n%s", want, out)
		}
	}
}

func TestPrintAgentRisk_NotConfigured(t *testing.T) {
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"agent_ref": "agent:x", "configured": false})
	}))
	defer gw.Close()
	t.Setenv("NIA_GATEWAY_URL", gw.URL)

	var buf bytes.Buffer
	printAgentRisk(&buf, "agent:x")
	if !strings.Contains(buf.String(), "monitoring is not configured") {
		t.Fatalf("got %q, want an honest not-configured message", buf.String())
	}
}

func TestPrintAgentRisk_UnreachableGateway(t *testing.T) {
	t.Setenv("NIA_GATEWAY_URL", "http://127.0.0.1:1")

	var buf bytes.Buffer
	printAgentRisk(&buf, "agent:x")
	if !strings.Contains(buf.String(), "could not reach the gateway") {
		t.Fatalf("got %q, want an honest error rather than a panic", buf.String())
	}
}

func TestPrintAgentRecentAudit_TruncatesToLimitMostRecentFirst(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /agents/agent:x/audit", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]map[string]any{
			{"Action": "one", "At": "2026-01-01T00:00:00Z"},
			{"Action": "two", "At": "2026-01-01T00:01:00Z"},
			{"Action": "three", "At": "2026-01-01T00:02:00Z"},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	t.Setenv("NIA_API_URL", srv.URL)

	var buf bytes.Buffer
	printAgentRecentAudit(&buf, "agent:x", 2)
	out := buf.String()
	threeIdx := strings.Index(out, "three")
	twoIdx := strings.Index(out, "two")
	if threeIdx == -1 || twoIdx == -1 || threeIdx > twoIdx {
		t.Fatalf("got %q, want the most recent two events, most recent first", out)
	}
	if strings.Contains(out, "one") {
		t.Fatalf("got %q, want the oldest event truncated away with -audit-limit 2", out)
	}
}
