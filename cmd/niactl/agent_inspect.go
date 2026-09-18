// cmd/niactl's agent inspect and risk commands. Everything else in
// this CLI shows one resource at a time, agent inspect is the first
// command that composes several endpoints (identity, credentials,
// grants, audit, blast radius, and a best-effort look at the
// gateway's own risk view) into one report, the shape an operator
// actually wants when an agent shows up in an incident: not five
// separate commands run by hand, one command that answers "what is
// this agent, what can it reach, and is it currently hot."
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
)

func cmdAgent(args []string) {
	if len(args) < 1 {
		usage()
		os.Exit(1)
	}
	switch args[0] {
	case "inspect":
		cmdAgentInspect(args[1:])
	default:
		usage()
		os.Exit(1)
	}
}

func cmdAgentInspect(args []string) {
	fs := flag.NewFlagSet("agent inspect", flag.ExitOnError)
	ref := fs.String("ref", "", "agent ref to inspect, e.g. agent:billing-reconciler")
	auditLimit := fs.Int("audit-limit", 10, "most recent audit events to show")
	_ = fs.Parse(args)

	if *ref == "" {
		fmt.Fprintln(os.Stderr, "agent inspect: -ref is required")
		os.Exit(1)
	}
	printAgentInspection(os.Stdout, *ref, *auditLimit)
}

func cmdRisk(args []string) {
	fs := flag.NewFlagSet("risk", flag.ExitOnError)
	ref := fs.String("ref", "", "agent ref to check")
	_ = fs.Parse(args)

	if *ref == "" {
		fmt.Fprintln(os.Stderr, "risk: -ref is required")
		os.Exit(1)
	}
	getGateway("/risk/" + url.PathEscape(*ref))
}

// printAgentInspection is the report body. Each section is independent:
// a failure or an empty result in one (no credentials issued, say)
// doesn't stop the rest from printing, the same "show what's known,
// say plainly what isn't" posture printScenarioAudit and
// printScenarioBlastRadius already take in simulate.go. The agent
// record itself is the one exception, nothing else is worth showing
// for a ref that was never registered.
func printAgentInspection(out io.Writer, ref string, auditLimit int) {
	agent, ok := fetchAgentRecord(out, ref)
	if !ok {
		return
	}
	printAgentRecord(out, agent)

	fmt.Fprintln(out, "\ncredentials:")
	printAgentCredentials(out, ref)

	fmt.Fprintln(out, "\ngrants:")
	printAgentGrants(out, ref)

	fmt.Fprintf(out, "\nrecent audit (last %d):\n", auditLimit)
	printAgentRecentAudit(out, ref, auditLimit)

	fmt.Fprintln(out, "\nblast radius:")
	printScenarioBlastRadius(out, ref)

	fmt.Fprintln(out, "\nrisk (gateway, best effort):")
	printAgentRisk(out, ref)
}

func fetchAgentRecord(out io.Writer, ref string) (map[string]any, bool) {
	resp, err := apiCall(http.MethodGet, "/agents/"+url.PathEscape(ref), nil)
	if err != nil {
		fmt.Fprintf(out, "could not reach the control-plane API at %s: %v\n", apiAddr(), err)
		return nil, false
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusNotFound {
		fmt.Fprintf(out, "%s is not registered\n", ref)
		return nil, false
	}
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(out, "unexpected status %d fetching %s: %s\n", resp.StatusCode, ref, raw)
		return nil, false
	}
	var agent map[string]any
	if err := json.Unmarshal(raw, &agent); err != nil {
		fmt.Fprintf(out, "could not parse the agent response: %v\n", err)
		return nil, false
	}
	return agent, true
}

func printAgentRecord(out io.Writer, agent map[string]any) {
	ref, _ := agent["Ref"].(string)
	owner, _ := agent["Owner"].(string)
	businessUnit, _ := agent["BusinessUnit"].(string)
	purpose, _ := agent["Purpose"].(string)
	assurance, _ := agent["Assurance"].(string)
	state, _ := agent["State"].(string)

	fmt.Fprintf(out, "agent: %s\n", ref)
	fmt.Fprintf(out, "  owner: %s\n", nonEmpty(owner))
	if businessUnit != "" {
		fmt.Fprintf(out, "  business unit: %s\n", businessUnit)
	}
	if purpose != "" {
		fmt.Fprintf(out, "  purpose: %s\n", purpose)
	}
	fmt.Fprintf(out, "  state: %s (assurance: %s)\n", nonEmpty(state), nonEmpty(assurance))
	if state == "killed" {
		incident, _ := agent["KillIncident"].(string)
		killedBy, _ := agent["KilledBy"].(string)
		fmt.Fprintf(out, "  killed by %s, incident %s\n", nonEmpty(killedBy), nonEmpty(incident))
	}
}

func printAgentCredentials(out io.Writer, ref string) {
	resp, err := apiCall(http.MethodGet, "/agents/"+url.PathEscape(ref)+"/credentials", nil)
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
	var creds []map[string]any
	if err := json.Unmarshal(raw, &creds); err != nil {
		fmt.Fprintf(out, "  could not parse the credentials response: %v\n", err)
		return
	}
	if len(creds) == 0 {
		fmt.Fprintln(out, "  (none issued)")
		return
	}
	for _, c := range creds {
		id, _ := c["ID"].(string)
		kind, _ := c["Kind"].(string)
		status, _ := c["Status"].(string)
		fmt.Fprintf(out, "  %s  %s  %s\n", id, kind, status)
	}
}

func printAgentGrants(out io.Writer, ref string) {
	resp, err := apiCall(http.MethodGet, "/agents/"+url.PathEscape(ref)+"/grants", nil)
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
	var grants []map[string]any
	if err := json.Unmarshal(raw, &grants); err != nil {
		fmt.Fprintf(out, "  could not parse the grants response: %v\n", err)
		return
	}
	if len(grants) == 0 {
		fmt.Fprintln(out, "  (none)")
		return
	}
	for _, g := range grants {
		kind, _ := g["Kind"].(string)
		switch kind {
		case "api_group":
			group, _ := g["Group"].(string)
			fmt.Fprintf(out, "  api_group:%s\n", group)
		case "endpoint":
			method, _ := g["Method"].(string)
			path, _ := g["Path"].(string)
			fmt.Fprintf(out, "  endpoint:%s %s\n", method, path)
		default:
			object, _ := g["Object"].(string)
			fmt.Fprintf(out, "  %s:%s\n", kind, object)
		}
	}
}

// printAgentRecentAudit shows the last auditLimit events for this agent,
// most recent first. GET /agents/{ref}/audit returns everything for the
// agent oldest first (see cmd/api's handleAgentAudit, it has no limit
// param of its own), so the truncation to "recent" is done here, client
// side, rather than asking the server for something it doesn't offer.
func printAgentRecentAudit(out io.Writer, ref string, limit int) {
	resp, err := apiCall(http.MethodGet, "/agents/"+url.PathEscape(ref)+"/audit", nil)
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
		fmt.Fprintln(out, "  (no events)")
		return
	}
	if limit > 0 && len(events) > limit {
		events = events[len(events)-limit:]
	}
	for i := len(events) - 1; i >= 0; i-- {
		e := events[i]
		action, _ := e["Action"].(string)
		detail, _ := e["Detail"].(string)
		at, _ := e["At"].(string)
		if detail != "" {
			fmt.Fprintf(out, "  %s  %s: %s\n", at, action, detail)
		} else {
			fmt.Fprintf(out, "  %s  %s\n", at, action)
		}
	}
}

// printAgentRisk is a best-effort look at the gateway's own view of
// this agent, GET /risk/{ref}. Best-effort because the gateway is a
// separate process from cmd/api, and monitoring on it is opt-in (see
// monitoring.ThresholdsFromEnv), so "the gateway is unreachable" and
// "monitoring isn't configured there" are both routine, not failures
// of the inspect command itself.
func printAgentRisk(out io.Writer, ref string) {
	// GET /risk/{ref} on the gateway needs an authenticated operator now
	// (see cmd/gateway's routes()), so this carries NIA_OPERATOR_TOKEN
	// the same way every control-plane call does.
	req, err := http.NewRequest(http.MethodGet, gatewayAddr()+"/risk/"+url.PathEscape(ref), nil)
	if err != nil {
		fmt.Fprintf(out, "  could not build the gateway request: %v\n", err)
		return
	}
	setOperatorAuth(req)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintf(out, "  could not reach the gateway at %s: %v\n", gatewayAddr(), err)
		return
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(out, "  unexpected status %d: %s\n", resp.StatusCode, raw)
		return
	}
	var report map[string]any
	if err := json.Unmarshal(raw, &report); err != nil {
		fmt.Fprintf(out, "  could not parse the risk response: %v\n", err)
		return
	}
	configured, _ := report["configured"].(bool)
	if !configured {
		fmt.Fprintln(out, "  monitoring is not configured on this gateway")
		return
	}
	cumulative, _ := report["cumulative"].(float64)
	fmt.Fprintf(out, "  cumulative risk: %.0f\n", cumulative)
	if thresholds, ok := report["thresholds"].(map[string]any); ok {
		flagAt, _ := thresholds["FlagAt"].(float64)
		revokeAt, _ := thresholds["RevokeAt"].(float64)
		killAt, _ := thresholds["KillAt"].(float64)
		fmt.Fprintf(out, "  thresholds: flag at %.0f, revoke at %.0f, kill at %.0f\n", flagAt, revokeAt, killAt)
	}
	if incidents, ok := report["incidents"].([]any); ok && len(incidents) > 0 {
		fmt.Fprintf(out, "  %d recent incident(s) on this gateway:\n", len(incidents))
		for _, raw := range incidents {
			in, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			action, _ := in["Action"].(string)
			reason, _ := in["Reason"].(string)
			fmt.Fprintf(out, "    %s: %s\n", action, reason)
		}
	}
}

func nonEmpty(s string) string {
	if strings.TrimSpace(s) == "" {
		return "(none)"
	}
	return s
}
