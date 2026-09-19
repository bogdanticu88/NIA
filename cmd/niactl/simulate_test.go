package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// TestScenarios_AgentHijackIsWellFormed catches the kind of mistake that
// would otherwise only surface at demo time: a step calling a tool the
// scenario never registers, or an initial grant naming a tool that
// isn't in the tools list. Both would make runScenario's transcript
// confusing without failing outright, this test fails outright instead.
func TestScenarios_AgentHijackIsWellFormed(t *testing.T) {
	sc, ok := scenarios()["agent-hijack"]
	if !ok {
		t.Fatal("agent-hijack scenario is not registered")
	}
	if sc.agentRef == "" {
		t.Fatal("agentRef is empty")
	}
	if len(sc.steps) == 0 {
		t.Fatal("scenario has no steps")
	}

	known := map[string]bool{}
	for _, tool := range sc.tools {
		if tool.name == "" {
			t.Fatal("a tool in the scenario has an empty name")
		}
		known[tool.name] = true
	}
	for _, g := range sc.initialGrants {
		if g.kind == "tool" && !known[g.object] {
			t.Fatalf("initial grant names tool %q, which the scenario never registers", g.object)
		}
	}
	for _, step := range sc.steps {
		if !known[step.tool] {
			t.Fatalf("attack step calls tool %q, which the scenario never registers", step.tool)
		}
	}
}

func TestPrintStepResult_Allowed(t *testing.T) {
	var buf bytes.Buffer
	res := stepResult{status: http.StatusOK, body: map[string]any{}}
	contained := printStepResult(&buf, 1, "agent:x", attackStep{tool: "invoice.read"}, res, false) != notContained
	if contained {
		t.Fatal("an ordinary 200 should not be reported as containment")
	}
	if !strings.Contains(buf.String(), "ALLOWED") {
		t.Fatalf("got %q, want it to say ALLOWED", buf.String())
	}
}

func TestPrintStepResult_AllowedButTagged_ReportsDetectedNotBlocked(t *testing.T) {
	var buf bytes.Buffer
	res := stepResult{status: http.StatusOK, body: map[string]any{}}
	contained := printStepResult(&buf, 1, "agent:x", attackStep{tool: "customer.export", tag: "privilege deviation"}, res, false) != notContained
	if contained {
		t.Fatal("a tagged-but-allowed call is a detection, not containment")
	}
	if !strings.Contains(buf.String(), "DETECTED") || !strings.Contains(buf.String(), "privilege deviation") {
		t.Fatalf("got %q, want DETECTED with the step's tag", buf.String())
	}
}

func TestPrintStepResult_Denied_ReportsContainment(t *testing.T) {
	var buf bytes.Buffer
	res := stepResult{status: http.StatusForbidden, body: map[string]any{"error": "agent is not authorized for this tool"}}
	contained := printStepResult(&buf, 1, "agent:x", attackStep{tool: "credential.read"}, res, false) != notContained
	if !contained {
		t.Fatal("a 403 must be reported as containment")
	}
	if !strings.Contains(buf.String(), "BLOCKED") {
		t.Fatalf("got %q, want BLOCKED", buf.String())
	}
}

func TestPrintStepResult_TransportError(t *testing.T) {
	var buf bytes.Buffer
	res := stepResult{err: os.ErrDeadlineExceeded}
	contained := printStepResult(&buf, 1, "agent:x", attackStep{tool: "invoice.read"}, res, false) != notContained
	if contained {
		t.Fatal("a transport error is not containment")
	}
	if !strings.Contains(buf.String(), "ERROR") {
		t.Fatalf("got %q, want ERROR", buf.String())
	}
}

func TestPrintStepRisk_ZeroValueAndCumulative_PrintsNothing(t *testing.T) {
	var buf bytes.Buffer
	printStepRisk(&buf, map[string]any{"value": 0.0, "cumulative": 0.0})
	if buf.Len() != 0 {
		t.Fatalf("got %q, want nothing printed for an all-zero risk block", buf.String())
	}
}

func TestPrintStepRisk_ValueAndSignals(t *testing.T) {
	var buf bytes.Buffer
	printStepRisk(&buf, map[string]any{
		"value":      4.0,
		"cumulative": 9.0,
		"action":     "none",
		"signals": []any{
			map[string]any{"name": "novel_tool", "weight": 3.0},
			map[string]any{"name": "risk_class:destructive", "weight": 1.0},
		},
	})
	out := buf.String()
	if !strings.Contains(out, "risk this call: 4") || !strings.Contains(out, "cumulative: 9") {
		t.Fatalf("got %q, want the call's own value and the running cumulative total", out)
	}
	if !strings.Contains(out, "novel_tool(+3)") {
		t.Fatalf("got %q, want the novel_tool signal listed", out)
	}
}

func TestPrintStepRisk_ActionReported(t *testing.T) {
	var buf bytes.Buffer
	printStepRisk(&buf, map[string]any{"value": 20.0, "cumulative": 20.0, "action": "kill"})
	if !strings.Contains(buf.String(), "monitoring action: kill") {
		t.Fatalf("got %q, want the kill action called out", buf.String())
	}
}

// fakeControlPlane is a minimal stand-in for cmd/api used to drive
// runScenario end to end without a real control-plane process. It
// records every request path so a test can assert on the setup
// sequence runScenario is supposed to produce.
type fakeControlPlane struct {
	t     *testing.T
	paths []string
	audit []map[string]any
}

func newFakeControlPlane(t *testing.T) *httptest.Server {
	fc := &fakeControlPlane{t: t}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /agents", func(w http.ResponseWriter, r *http.Request) {
		fc.paths = append(fc.paths, "POST /agents")
		w.WriteHeader(http.StatusCreated)
	})
	mux.HandleFunc("POST /tools", func(w http.ResponseWriter, r *http.Request) {
		fc.paths = append(fc.paths, "POST /tools")
		w.WriteHeader(http.StatusCreated)
	})
	mux.HandleFunc("POST /agents/{ref}/grants", func(w http.ResponseWriter, r *http.Request) {
		fc.paths = append(fc.paths, "POST /agents/"+r.PathValue("ref")+"/grants")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode([]map[string]string{})
	})
	mux.HandleFunc("POST /agents/{ref}/credentials", func(w http.ResponseWriter, r *http.Request) {
		fc.paths = append(fc.paths, "POST /agents/"+r.PathValue("ref")+"/credentials")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{"ID": "cred-fake", "secret": "fake-secret"})
	})
	mux.HandleFunc("GET /agents/{ref}/audit", func(w http.ResponseWriter, r *http.Request) {
		fc.paths = append(fc.paths, "GET /agents/"+r.PathValue("ref")+"/audit")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode([]map[string]any{{"action": "agent.registered"}})
	})
	mux.HandleFunc("GET /graph/{ref}/blast-radius", func(w http.ResponseWriter, r *http.Request) {
		fc.paths = append(fc.paths, "GET /graph/"+r.PathValue("ref")+"/blast-radius")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{
			"id":       r.PathValue("ref"),
			"total":    2,
			"by_kind":  map[string]int{"tool": 2},
			"severity": "MEDIUM",
		})
	})
	return httptest.NewServer(mux)
}

// TestRunScenario_DrivesRealSetupCallsAndDetectsContainment exercises
// runScenario against fake cmd/api and cmd/gateway servers, standing in
// for the real processes so the test stays fast and deterministic while
// still asserting on the actual HTTP call sequence runScenario makes,
// not a description of it.
func TestRunScenario_DrivesRealSetupCallsAndDetectsContainment(t *testing.T) {
	api := newFakeControlPlane(t)
	defer api.Close()

	callCount := 0
	var sawAuth []string
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		sawAuth = append(sawAuth, r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		if callCount == 1 {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]any{"agent": "agent:test", "tool": "invoice.read", "status": "allowed"})
			return
		}
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]any{"error": "agent is not authorized for this tool"})
	}))
	defer gateway.Close()

	t.Setenv("NIA_API_URL", api.URL)
	t.Setenv("NIA_GATEWAY_URL", gateway.URL)

	sc := scenario{
		name:        "test-scenario",
		description: "a two-step scenario for exercising runScenario's own plumbing",
		agentRef:    "agent:test",
		owner:       "test",
		purpose:     "test",
		tools: []toolSpec{
			{name: "invoice.read", riskClass: "read_only", description: "read invoices"},
		},
		initialGrants: []grantSpec{
			{kind: "tool", object: "invoice.read"},
		},
		steps: []attackStep{
			{tool: "invoice.read"},
			{tool: "invoice.read", tag: "post-containment check"},
		},
	}

	var out bytes.Buffer
	runScenario(sc, &out)
	got := out.String()

	if !strings.Contains(got, "ALLOWED") {
		t.Fatalf("transcript missing the first, allowed call:\n%s", got)
	}
	if !strings.Contains(got, "BLOCKED") {
		t.Fatalf("transcript missing the second, blocked call:\n%s", got)
	}
	if !strings.Contains(got, "consistent with the kill switch having fired mid-sequence") {
		t.Fatalf("transcript did not report containment despite a 403 on the second call:\n%s", got)
	}
	if callCount != 2 {
		t.Fatalf("gateway received %d calls, want 2", callCount)
	}
	for i, got := range sawAuth {
		if got != "Bearer cred-fake.fake-secret" {
			t.Fatalf("call %d: Authorization = %q, want the credential issueScenarioCredential minted, proving the scenario authenticates the same way a real caller now must", i+1, got)
		}
	}
	if !strings.Contains(got, "severity MEDIUM") {
		t.Fatalf("transcript missing the blast-radius summary read back from the graph:\n%s", got)
	}
}

func TestPrintScenarioBlastRadius_PrintsTotalAndSeverity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"total":               3,
			"by_kind":             map[string]int{"tool": 2, "data": 1},
			"severity":            "HIGH",
			"critical_resources":  []string{"customers.ssn"},
			"sensitive_resources": []string{},
		})
	}))
	defer srv.Close()
	t.Setenv("NIA_API_URL", srv.URL)

	var buf bytes.Buffer
	printScenarioBlastRadius(&buf, "agent:test")
	out := buf.String()
	if !strings.Contains(out, "3 node(s) reachable, severity HIGH") {
		t.Fatalf("got %q, want the total and severity reported", out)
	}
	if !strings.Contains(out, "customers.ssn") {
		t.Fatalf("got %q, want the critical resource named", out)
	}
}

func TestPrintScenarioBlastRadius_UnreachableAPI(t *testing.T) {
	t.Setenv("NIA_API_URL", "http://127.0.0.1:1")

	var buf bytes.Buffer
	printScenarioBlastRadius(&buf, "agent:test")
	if !strings.Contains(buf.String(), "could not reach") {
		t.Fatalf("got %q, want an honest error rather than a panic", buf.String())
	}
}

// Test401BeforeContainmentIsStillUnexpected keeps the bug fix from
// swallowing the failure it used to be confused with. A 401 before
// anything crossed a threshold means the two processes have no shared
// credential store, which is the single most common way this scenario
// is run wrong, and it has to keep reading as wrong.
func Test401BeforeContainmentIsStillUnexpected(t *testing.T) {
	var buf bytes.Buffer
	res := stepResult{status: http.StatusUnauthorized, body: map[string]any{"error": "could not resolve caller identity"}}
	got := printStepResult(&buf, 1, "agent:x", attackStep{tool: "invoice.read"}, res, false)
	if got != notContained {
		t.Errorf("containment = %q, want %q: a 401 with no prior containment is a misconfiguration, not a success", got, notContained)
	}
	if !strings.Contains(buf.String(), "UNEXPECTED") {
		t.Errorf("transcript = %q, want it to still say UNEXPECTED", buf.String())
	}
}

// Test401AfterContainmentIsTheContainmentWorking is the fix itself. Once
// revoke or kill has fired, the agent's credential is gone, so the next
// call cannot authenticate. That used to print UNEXPECTED and report
// "no previously-allowed call was denied", which told the reader the run
// had failed at the exact moment it had succeeded.
func Test401AfterContainmentIsTheContainmentWorking(t *testing.T) {
	var buf bytes.Buffer
	res := stepResult{status: http.StatusUnauthorized, body: map[string]any{"error": "could not resolve caller identity"}}
	got := printStepResult(&buf, 6, "agent:x", attackStep{tool: "database.query"}, res, true)
	if got != cutOffByRevocation {
		t.Errorf("containment = %q, want %q", got, cutOffByRevocation)
	}
	out := buf.String()
	if strings.Contains(out, "UNEXPECTED") {
		t.Errorf("transcript = %q, should not call a revoked credential unexpected", out)
	}
	if !strings.Contains(out, "CUT OFF") {
		t.Errorf("transcript = %q, want it to say the agent was cut off", out)
	}
}

// TestStepActionReadsTheMonitoringAction covers the input the loop uses
// to decide whether containment has fired, since getting that wrong
// would silently restore the old behaviour.
func TestStepActionReadsTheMonitoringAction(t *testing.T) {
	cases := []struct {
		name string
		res  stepResult
		want string
	}{
		{"kill", stepResult{body: map[string]any{"risk": map[string]any{"action": "kill"}}}, "kill"},
		{"revoke", stepResult{body: map[string]any{"risk": map[string]any{"action": "revoke"}}}, "revoke"},
		{"flag", stepResult{body: map[string]any{"risk": map[string]any{"action": "flag"}}}, "flag"},
		{"no risk block at all", stepResult{body: map[string]any{}}, ""},
		{"risk block with no action", stepResult{body: map[string]any{"risk": map[string]any{}}}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := stepAction(tc.res); got != tc.want {
				t.Errorf("stepAction = %q, want %q", got, tc.want)
			}
		})
	}
}
