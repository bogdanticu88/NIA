package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// attackStep is one call a scenario drives through the real gateway.
// tag is empty for ordinary expected traffic; set, it marks a step
// that's authorized but shouldn't be, what the transcript calls
// "DETECTED" when the gateway still allows it, the risk engine's job to
// catch, not the policy layer's.
type attackStep struct {
	tool      string
	arguments map[string]any
	tag       string
}

type toolSpec struct {
	name        string
	riskClass   string
	description string
}

type grantSpec struct {
	kind   string
	object string
}

// scenario is a deterministic, scripted sequence this command drives
// end to end through the real control-plane API and the real gateway,
// not printed output standing in for one. Every step in the transcript
// this produces corresponds to an actual HTTP call and an actual
// response from a real NIA process.
type scenario struct {
	name          string
	description   string
	agentRef      string
	owner         string
	purpose       string
	tools         []toolSpec
	initialGrants []grantSpec
	steps         []attackStep
}

func scenarios() map[string]scenario {
	return map[string]scenario{
		"agent-hijack": agentHijackScenario(),
	}
}

// agentHijackScenario models an invoice-processing agent with broader
// tool access than its established behavior ever uses, a realistic
// over-privileged setup, not a contrived one: the coarse authorization
// layer says this agent CAN call all seven tools, its normal work only
// ever touches the first three. That gap between "authorized" and
// "actually used" is exactly what internal/risk's novel_tool and
// risk_class signals exist to catch, an allowed call that's still
// wrong, not a call the policy layer should have blocked outright.
// customers.ssn is deliberately left ungranted at the data level, so
// the database.query step gets a real, separate denial from
// cmd/gateway's argument inspection, not just a risk flag, proving the
// Agent+Tool+Resource decision, not only Agent+Tool.
func agentHijackScenario() scenario {
	return scenario{
		name:        "agent-hijack",
		description: "an invoice-processing agent behaves normally, then a hijacked session escalates toward credential access and data exfiltration",
		agentRef:    "agent:invoice-agent",
		owner:       "niactl-simulate",
		purpose:     "simulated invoice agent for the agent-hijack scenario",
		tools: []toolSpec{
			{name: "invoice.read", riskClass: "read_only", description: "read invoice records"},
			{name: "customer.read", riskClass: "read_only", description: "read customer records"},
			{name: "payment.lookup", riskClass: "read_only", description: "look up a payment"},
			{name: "customer.export", riskClass: "destructive", description: "bulk export customer records"},
			{name: "credential.read", riskClass: "destructive", description: "read another identity's credential metadata"},
			{name: "database.query", riskClass: "read_only", description: "ad hoc query against the customer database"},
			{name: "external.upload", riskClass: "destructive", description: "upload a file to an external endpoint"},
		},
		initialGrants: []grantSpec{
			{kind: "tool", object: "invoice.read"},
			{kind: "tool", object: "customer.read"},
			{kind: "tool", object: "payment.lookup"},
			{kind: "tool", object: "customer.export"},
			{kind: "tool", object: "credential.read"},
			{kind: "tool", object: "database.query"},
			{kind: "tool", object: "external.upload"},
			{kind: "data", object: "customers.name"},
		},
		steps: []attackStep{
			{tool: "invoice.read"},
			{tool: "customer.read"},
			{tool: "payment.lookup"},
			{tool: "customer.export", tag: "new tool, privilege deviation"},
			{tool: "credential.read", tag: "privilege escalation attempt"},
			{tool: "database.query", arguments: map[string]any{"table": "customers", "columns": []any{"name", "ssn"}}, tag: "sensitive data access (customers.ssn)"},
			{tool: "external.upload", tag: "exfiltration attempt"},
			{tool: "invoice.read", tag: "post-containment check, a tool this agent was granted and had already used successfully"},
		},
	}
}

func cmdSimulate(args []string) {
	if len(args) < 1 || args[0] != "attack" {
		usage()
		os.Exit(1)
	}
	fs := flag.NewFlagSet("simulate attack", flag.ExitOnError)
	name := fs.String("scenario", "", "scenario to run, e.g. agent-hijack")
	_ = fs.Parse(args[1:])

	sc, ok := scenarios()[*name]
	if !ok {
		fmt.Fprintf(os.Stderr, "simulate attack: unknown scenario %q, known scenarios: agent-hijack\n", *name)
		os.Exit(1)
	}
	runScenario(sc, os.Stdout)
}

// runScenario drives sc end to end and writes a transcript to out.
// Every line is either a real setup call against cmd/api or a real
// tool call against cmd/gateway; this function makes no decision about
// allow/deny/risk itself, it only calls the real pipeline and reports
// what came back.
func runScenario(sc scenario, out io.Writer) {
	fmt.Fprintf(out, "=== NIA attack simulation: %s ===\n%s\n\n", sc.name, sc.description)

	fmt.Fprintln(out, "[setup]")
	registerScenarioAgent(out, sc)
	for _, t := range sc.tools {
		registerScenarioTool(out, t)
	}
	writeScenarioGrants(out, sc)
	credential := issueScenarioCredential(out, sc)

	fmt.Fprintln(out, "\n[attack sequence]")
	how := notContained
	fired := false
	for i, step := range sc.steps {
		res := runStep(sc.agentRef, credential, step)
		if c := printStepResult(out, i+1, sc.agentRef, step, res, fired); c != notContained && how == notContained {
			// First one wins: the interesting fact is how the agent was
			// stopped, and every step after that is a consequence.
			how = c
		}
		if a := stepAction(res); a == "revoke" || a == "kill" {
			fired = true
		}
	}

	fmt.Fprintln(out, "\n[result]")
	switch how {
	case cutOffByRevocation:
		fmt.Fprintf(out, "%s was cut off mid-sequence. Crossing a revoke or kill threshold revokes the agent's credential through the shared credential store, so every later call fails at authentication: the agent cannot present a credential that still exists, let alone reach the authorization check. This is enforcement, not a printed result.\n", sc.agentRef)
	case blockedByPolicy:
		fmt.Fprintf(out, "%s was denied a call after previously being granted and successfully using that same tool, consistent with the kill switch having fired mid-sequence: policy.Check now reads the kill sentinel for this agent rather than its prior grants, this is enforcement, not a printed result.\n", sc.agentRef)
	default:
		fmt.Fprintln(out, "no previously-allowed call was denied during this run. Either nothing here crossed a configured risk threshold, or the gateway wasn't started with NIA_RISK_FLAG_AT / NIA_RISK_REVOKE_AT / NIA_RISK_KILL_AT set, monitoring is off by default, see deployments/docker-compose.yml's comment on those three variables.")
	}

	fmt.Fprintln(out, "\ncontrol-plane audit trail (cmd/api's own view; it will not include the gateway's gateway.* and monitoring.* events unless NIA_AUDIT_DATABASE_URL points both processes at the same backend, see docker-compose.yml):")
	printScenarioAudit(out, sc.agentRef)

	fmt.Fprintln(out, "\nblast radius (what this agent's own grants reached in the identity graph, auto-populated as writeScenarioGrants ran, not hand-built):")
	printScenarioBlastRadius(out, sc.agentRef)
}

func apiCall(method, path string, body []byte) (*http.Response, error) {
	req, err := http.NewRequest(method, apiAddr()+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	setOperatorAuth(req)
	return http.DefaultClient.Do(req)
}

func registerScenarioAgent(out io.Writer, sc scenario) {
	body, _ := json.Marshal(map[string]string{"ref": sc.agentRef, "owner": sc.owner, "purpose": sc.purpose})
	resp, err := apiCall(http.MethodPost, "/agents", body)
	if err != nil {
		fmt.Fprintf(out, "  could not reach the control-plane API at %s: %v\n", apiAddr(), err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusCreated:
		fmt.Fprintf(out, "  registered %s\n", sc.agentRef)
	case http.StatusConflict:
		fmt.Fprintf(out, "  %s already registered, continuing\n", sc.agentRef)
	default:
		raw, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(out, "  unexpected status %d registering %s: %s\n", resp.StatusCode, sc.agentRef, raw)
		os.Exit(1)
	}
}

func registerScenarioTool(out io.Writer, t toolSpec) {
	body, _ := json.Marshal(map[string]string{"name": t.name, "description": t.description, "risk_class": t.riskClass})
	resp, err := apiCall(http.MethodPost, "/tools", body)
	if err != nil {
		fmt.Fprintf(out, "  could not reach the control-plane API at %s: %v\n", apiAddr(), err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusCreated:
		fmt.Fprintf(out, "  registered tool %s (%s)\n", t.name, t.riskClass)
	case http.StatusConflict:
		fmt.Fprintf(out, "  tool %s already registered, continuing\n", t.name)
	default:
		raw, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(out, "  unexpected status %d registering tool %s: %s\n", resp.StatusCode, t.name, raw)
		os.Exit(1)
	}
}

func writeScenarioGrants(out io.Writer, sc scenario) {
	grants := make([]map[string]string, 0, len(sc.initialGrants))
	for _, g := range sc.initialGrants {
		grants = append(grants, map[string]string{"kind": g.kind, "object": g.object})
	}
	body, _ := json.Marshal(map[string]any{"grants": grants, "operator": "niactl-simulate"})
	resp, err := apiCall(http.MethodPost, "/agents/"+url.PathEscape(sc.agentRef)+"/grants", body)
	if err != nil {
		fmt.Fprintf(out, "  could not reach the control-plane API at %s: %v\n", apiAddr(), err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(out, "  unexpected status %d writing grants: %s\n", resp.StatusCode, raw)
		os.Exit(1)
	}
	fmt.Fprintf(out, "  granted %d starting permission(s) to %s\n", len(sc.initialGrants), sc.agentRef)
}

// issueScenarioCredential mints a real bearer credential for the
// scenario agent, the same POST /agents/{ref}/credentials handleIssueCredential
// serves for credential issue, and returns it as "id.secret", the exact
// shape callGateway presents as "Authorization: Bearer <id.secret>".
// Before credentialResolver became the gateway's default, this scenario
// authenticated with nothing but an X-Agent-Ref header, which is the
// specific gap the security hardening pass closed, see
// docs/ARCHITECTURE.md's "Credential-backed authentication and state
// convergence"; the simulation has to authenticate the same way a real
// caller now must, or it would stop proving anything about the actual
// runtime path the moment credentialResolver shipped.
func issueScenarioCredential(out io.Writer, sc scenario) string {
	body, _ := json.Marshal(map[string]any{
		"kind":     "api_key",
		"operator": "niactl-simulate",
	})
	resp, err := apiCall(http.MethodPost, "/agents/"+url.PathEscape(sc.agentRef)+"/credentials", body)
	if err != nil {
		fmt.Fprintf(out, "  could not reach the control-plane API at %s: %v\n", apiAddr(), err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		fmt.Fprintf(out, "  unexpected status %d issuing a credential for %s: %s\n", resp.StatusCode, sc.agentRef, raw)
		os.Exit(1)
	}
	var issued struct {
		ID     string
		Secret string
	}
	if err := json.Unmarshal(raw, &issued); err != nil || issued.ID == "" || issued.Secret == "" {
		fmt.Fprintf(out, "  could not parse the credential issued for %s: %s\n", sc.agentRef, raw)
		os.Exit(1)
	}
	fmt.Fprintf(out, "  issued %s a credential (%s), presenting it on every step below\n", sc.agentRef, issued.ID)
	return issued.ID + "." + issued.Secret
}

type stepResult struct {
	status int
	body   map[string]any
	err    error
}

func runStep(agentRef, credential string, step attackStep) stepResult {
	argsJSON := ""
	if len(step.arguments) > 0 {
		b, _ := json.Marshal(step.arguments)
		argsJSON = string(b)
	}
	resp, err := callGateway(agentRef, credential, step.tool, argsJSON)
	if err != nil {
		return stepResult{err: err}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var body map[string]any
	_ = json.Unmarshal(raw, &body)
	return stepResult{status: resp.StatusCode, body: body}
}

// printStepResult writes one step's outcome and reports whether it was
// a 403 denial, the signal runScenario uses to decide whether
// containment fired: a call denied after the agent was granted and had
// already successfully used that same tool is what a kill mid-sequence
// looks like from the caller's side.
// containment is how, if at all, a step showed the control plane
// actually stopping the agent. There are two shapes and they happen at
// different layers, which is the whole reason this is not a bool.
type containment string

const (
	notContained containment = ""
	// blockedByPolicy is a 403: the agent still authenticates, and the
	// authorization check refuses the call because the kill sentinel is
	// set rather than because the grant is gone.
	blockedByPolicy containment = "blocked"
	// cutOffByRevocation is a 401 after containment fired: revoke and
	// kill both revoke the agent's credential now, so the next call
	// fails at authentication and never reaches authorization at all.
	cutOffByRevocation containment = "cut_off"
)

// stepAction is the monitoring action the gateway reported for a step,
// "flag", "revoke", "kill", or empty.
func stepAction(res stepResult) string {
	risk, ok := res.body["risk"].(map[string]any)
	if !ok {
		return ""
	}
	action, _ := risk["action"].(string)
	return action
}

// printStepResult renders one step and says whether it demonstrated
// containment.
//
// fired says whether an earlier step already crossed a revoke or kill
// threshold, and it is what makes a 401 readable. Before containment, a
// 401 means the setup is wrong, almost always two processes with no
// shared credential store, and calling that "expected" would hide a
// real misconfiguration. After containment, a 401 is the containment
// working: the credential it was using no longer exists. Same status
// code, opposite meanings, and the transcript used to print both as
// "UNEXPECTED", which said the run had failed when it had just
// succeeded.
func printStepResult(out io.Writer, n int, agentRef string, step attackStep, res stepResult, fired bool) containment {
	fmt.Fprintf(out, "[%02d] %s -> %s\n", n, agentRef, step.tool)
	switch {
	case res.err != nil:
		fmt.Fprintf(out, "     ERROR: %v\n", res.err)
		return notContained
	case res.status == http.StatusOK:
		if step.tag != "" {
			fmt.Fprintf(out, "     DETECTED: %s (call was allowed, flagged for review, not blocked outright)\n", step.tag)
		} else {
			fmt.Fprintln(out, "     ALLOWED")
		}
		if risk, ok := res.body["risk"].(map[string]any); ok {
			printStepRisk(out, risk)
		}
		return notContained
	case res.status == http.StatusForbidden:
		reason, _ := res.body["error"].(string)
		fmt.Fprintf(out, "     BLOCKED (%s)\n", reason)
		return blockedByPolicy
	case res.status == http.StatusUnauthorized && fired:
		fmt.Fprintln(out, "     CUT OFF (the credential was revoked by the containment above, this call fails at authentication and never reaches the authorization check)")
		return cutOffByRevocation
	default:
		reason, _ := res.body["error"].(string)
		fmt.Fprintf(out, "     UNEXPECTED (%d): %s\n", res.status, reason)
		return notContained
	}
}

func printStepRisk(out io.Writer, risk map[string]any) {
	value, _ := risk["value"].(float64)
	cumulative, _ := risk["cumulative"].(float64)
	action, _ := risk["action"].(string)
	if value == 0 && cumulative == 0 {
		return
	}
	fmt.Fprintf(out, "     risk this call: %.0f, cumulative: %.0f", value, cumulative)
	if sigs, ok := risk["signals"].([]any); ok && len(sigs) > 0 {
		parts := make([]string, 0, len(sigs))
		for _, s := range sigs {
			m, ok := s.(map[string]any)
			if !ok {
				continue
			}
			name, _ := m["name"].(string)
			weight, _ := m["weight"].(float64)
			parts = append(parts, fmt.Sprintf("%s(+%.0f)", name, weight))
		}
		if len(parts) > 0 {
			fmt.Fprintf(out, "  [%s]", strings.Join(parts, ", "))
		}
	}
	if action != "" && action != "none" {
		fmt.Fprintf(out, "  monitoring action: %s", action)
	}
	fmt.Fprintln(out)
}

func printScenarioAudit(out io.Writer, agentRef string) {
	resp, err := apiCall(http.MethodGet, "/agents/"+url.PathEscape(agentRef)+"/audit", nil)
	if err != nil {
		fmt.Fprintf(out, "  could not reach the control-plane API: %v\n", err)
		return
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(out, "  unexpected status %d: %s\n", resp.StatusCode, raw)
		return
	}
	var events []map[string]any
	if err := json.Unmarshal(raw, &events); err != nil {
		fmt.Fprintf(out, "  could not parse the audit response: %v\n", err)
		return
	}
	if len(events) == 0 {
		fmt.Fprintln(out, "  (no events on cmd/api's own audit sink)")
		return
	}
	for _, e := range events {
		action, _ := e["action"].(string)
		detail, _ := e["detail"].(string)
		if detail != "" {
			fmt.Fprintf(out, "  %s: %s\n", action, detail)
		} else {
			fmt.Fprintf(out, "  %s\n", action)
		}
	}
}

// printScenarioBlastRadius reads back GET /graph/{ref}/blast-radius,
// the same auto-populated edges writeScenarioGrants' calls to
// cmd/api's grant-writing endpoint already created, see
// docs/ARCHITECTURE.md's identity graph section for how severity is
// decided. This is read-only, it does not change anything the attack
// sequence already did, it just shows what an incident review would
// see if they asked "what could this agent reach" right after this run.
func printScenarioBlastRadius(out io.Writer, agentRef string) {
	resp, err := apiCall(http.MethodGet, "/graph/"+url.PathEscape(agentRef)+"/blast-radius", nil)
	if err != nil {
		fmt.Fprintf(out, "  could not reach the control-plane API: %v\n", err)
		return
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(out, "  unexpected status %d: %s\n", resp.StatusCode, raw)
		return
	}
	var br map[string]any
	if err := json.Unmarshal(raw, &br); err != nil {
		fmt.Fprintf(out, "  could not parse the blast-radius response: %v\n", err)
		return
	}
	total, _ := br["total"].(float64)
	severity, _ := br["severity"].(string)
	fmt.Fprintf(out, "  %.0f node(s) reachable, severity %s\n", total, severity)
	if byKind, ok := br["by_kind"].(map[string]any); ok && len(byKind) > 0 {
		parts := make([]string, 0, len(byKind))
		for kind, count := range byKind {
			parts = append(parts, fmt.Sprintf("%s:%.0f", kind, count))
		}
		fmt.Fprintf(out, "  by kind: %s\n", strings.Join(parts, ", "))
	}
	if critical, ok := br["critical_resources"].([]any); ok && len(critical) > 0 {
		fmt.Fprintf(out, "  critical resources reachable: %v\n", critical)
	}
}
