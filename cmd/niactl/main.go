// cmd/niactl is the operator CLI: register an agent, grant or revoke
// permissions, pull the kill switch, restore a killed agent, inspect
// current state, and review the audit trail. It talks to cmd/api over
// HTTP; it holds no state of its own and implements no policy logic,
// everything here is a thin wrapper around the control-plane API's
// HTTP surface.
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
	"time"
)

func apiAddr() string {
	if v := os.Getenv("NIA_API_URL"); v != "" {
		return v
	}
	return "http://localhost:8080"
}

func gatewayAddr() string {
	if v := os.Getenv("NIA_GATEWAY_URL"); v != "" {
		return v
	}
	return "http://localhost:8081"
}

func usage() {
	fmt.Fprintln(os.Stderr, `niactl - NIA operator CLI

Usage:
  niactl register -ref <agent_ref> [-owner <owner>] [-purpose <purpose>]
  niactl list
  niactl kill -ref <agent_ref> -incident <incident_id> [-operator <name>]
  niactl audit [-ref <agent_ref>] [-limit <n>]
  niactl credential issue -ref <agent_ref> -kind <api_key|oauth_token|mtls_cert> [-ttl <duration>]
  niactl credential list -ref <agent_ref>
  niactl credential revoke -id <credential_id> [-reason <reason>] [-operator <name>]
  niactl tool register -name <tool_name> [-description <text>] [-transport <mcp|http|grpc>] [-risk <read_only|write|destructive>] [-owner <owner>]
  niactl tool list
  niactl tool get -name <tool_name>
  niactl graph add-node -id <node_id> -kind <human|agent|tool|data>
  niactl graph add-edge -from <node_id> -to <node_id> -kind <owns|delegates_to|trusts|member_of|grants|bound_to>
  niactl graph neighbors -id <node_id> -kind <edge_kind>
  niactl graph reachable -id <node_id> [-kinds <edge_kind,edge_kind,...>]
  niactl grant write -ref <agent_ref> -kind <api_group|endpoint|tool|data> [-group <g>] [-method <m>] [-path <p>] [-object <o>] [-operator <name>]
  niactl grant delete -ref <agent_ref> -kind <...> [-group|-method|-path|-object matching what was written] [-operator <name>]
  niactl grant list -ref <agent_ref>
  niactl gateway call -ref <agent_ref> -tool <tool_name> [-arguments '<json object>']
  niactl simulate attack -scenario <agent-hijack>

audit with -ref shows everything recorded for that agent (registration,
grants, kills, every gateway decision), oldest first, the query an
incident review starts with. Without -ref it shows the n most recent
events across every agent (default 100).

credential issue only mints metadata, an id, kind, and expiry, NIA does not
generate the credential material itself, see internal/credentials's package
doc for why. -ttl takes a Go duration (24h, 30m); omitted or zero means no
expiry. credential revoke retires one key without touching the agent's
grants or identity, use kill instead when the agent itself is compromised.

tool register onboards a callable tool into the catalog, -risk defaults to
read_only, set it honestly, it's what internal/risk will eventually score
calls against. When the gateway is started with NIA_TOOLS_API_URL set, it
checks a tool against this catalog before checking policy, an unregistered
name is rejected outright; unset, that step is skipped and registering a
tool is bookkeeping only, see cmd/gateway's package doc comment.

grant write/delete/list are the missing half of Permissions: internal/policy
has always had WriteGrants/DeleteGrants/ListGrants, this is the first CLI
surface for them. -kind selects which of Grant's four shapes this is:
api_group needs -group, endpoint needs -method and -path, tool and data both
need -object, a tool name or a resource name respectively, the same names
niactl tool register and internal/sensitivity use. Writing is additive, it
diffs against what the agent already has and only adds what's missing,
niactl grant write called twice with the same grant is a no-op the second
time, not an error.

graph add-node/add-edge build the identity graph by hand, a node id is
whatever internal/graph's node kind implies, "agent:billing-reconciler" for
an agent, a human or tool or data resource id for the rest, adding a node
does not require it to also be registered through niactl register or niactl
tool register, the graph is independent bookkeeping. graph neighbors is one
hop out along a single edge kind; graph reachable follows edges
transitively, the blast-radius query, what a compromised node could reach
either way, defaulting to every edge kind when -kinds is omitted.

gateway call drives the gateway's own hot path directly, POST /tools/{tool}/call
with -ref sent as X-Agent-Ref and -arguments (a JSON object, optional) as the
request body's arguments field, the exact request an MCP-aware caller sends.
This is what makes niactl simulate possible: every step it prints is a real
gateway call through this same path, not printed output pretending to be one.

simulate attack drives a scripted, deterministic scenario end to end through
the real control-plane API and the real gateway: registers the scenario's
agent, registers its tools, writes its starting grants, then issues the
scenario's sequence of gateway calls in order, printing each one's real
outcome, allowed, denied, and, once configured with risk thresholds (see
deployments/docker-compose.yml's comment on NIA_RISK_FLAG_AT and friends),
watches containment actually fire and the agent's next request actually get
blocked. A re-run against an already-registered agent picks up where the
grants and tool catalog left off rather than failing, registration and
WriteGrants both tolerate "already exists," so running the same scenario
twice is safe, though a prior run's kill or accumulated risk carries
forward since there is no reset endpoint yet. Currently one scenario,
agent-hijack, see cmd/niactl/simulate.go for the full step-by-step script.

Every command talks to the control-plane API (NIA_API_URL, default http://localhost:8080)
except gateway call and simulate attack, which also talk to the gateway
(NIA_GATEWAY_URL, default http://localhost:8081).`)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "register":
		cmdRegister(os.Args[2:])
	case "list":
		cmdList(os.Args[2:])
	case "kill":
		cmdKill(os.Args[2:])
	case "audit":
		cmdAudit(os.Args[2:])
	case "credential":
		cmdCredential(os.Args[2:])
	case "tool":
		cmdTool(os.Args[2:])
	case "graph":
		cmdGraph(os.Args[2:])
	case "grant":
		cmdGrant(os.Args[2:])
	case "gateway":
		cmdGateway(os.Args[2:])
	case "simulate":
		cmdSimulate(os.Args[2:])
	default:
		usage()
		os.Exit(1)
	}
}

func cmdTool(args []string) {
	if len(args) < 1 {
		usage()
		os.Exit(1)
	}
	switch args[0] {
	case "register":
		cmdToolRegister(args[1:])
	case "list":
		cmdToolList(args[1:])
	case "get":
		cmdToolGet(args[1:])
	default:
		usage()
		os.Exit(1)
	}
}

func cmdCredential(args []string) {
	if len(args) < 1 {
		usage()
		os.Exit(1)
	}
	switch args[0] {
	case "issue":
		cmdCredentialIssue(args[1:])
	case "list":
		cmdCredentialList(args[1:])
	case "revoke":
		cmdCredentialRevoke(args[1:])
	default:
		usage()
		os.Exit(1)
	}
}

func cmdGraph(args []string) {
	if len(args) < 1 {
		usage()
		os.Exit(1)
	}
	switch args[0] {
	case "add-node":
		cmdGraphAddNode(args[1:])
	case "add-edge":
		cmdGraphAddEdge(args[1:])
	case "neighbors":
		cmdGraphNeighbors(args[1:])
	case "reachable":
		cmdGraphReachable(args[1:])
	default:
		usage()
		os.Exit(1)
	}
}

func cmdGrant(args []string) {
	if len(args) < 1 {
		usage()
		os.Exit(1)
	}
	switch args[0] {
	case "write":
		cmdGrantWrite(args[1:])
	case "delete":
		cmdGrantDelete(args[1:])
	case "list":
		cmdGrantList(args[1:])
	default:
		usage()
		os.Exit(1)
	}
}

func cmdGateway(args []string) {
	if len(args) < 1 {
		usage()
		os.Exit(1)
	}
	switch args[0] {
	case "call":
		cmdGatewayCall(args[1:])
	default:
		usage()
		os.Exit(1)
	}
}

func cmdRegister(args []string) {
	fs := flag.NewFlagSet("register", flag.ExitOnError)
	ref := fs.String("ref", "", "canonical agent ref, e.g. agent:billing-reconciler")
	owner := fs.String("owner", "", "human or team accountable for this agent")
	purpose := fs.String("purpose", "", "what this agent is for")
	_ = fs.Parse(args)

	if *ref == "" {
		fmt.Fprintln(os.Stderr, "register: -ref is required")
		os.Exit(1)
	}

	body, _ := json.Marshal(map[string]string{
		"ref":     *ref,
		"owner":   *owner,
		"purpose": *purpose,
	})
	post("/agents", body)
}

func cmdList(_ []string) {
	get("/agents")
}

func cmdKill(args []string) {
	fs := flag.NewFlagSet("kill", flag.ExitOnError)
	ref := fs.String("ref", "", "agent ref to kill")
	incident := fs.String("incident", "", "incident id this kill is tied to")
	operator := fs.String("operator", "niactl", "who is pulling the switch")
	_ = fs.Parse(args)

	if *ref == "" || *incident == "" {
		fmt.Fprintln(os.Stderr, "kill: -ref and -incident are required")
		os.Exit(1)
	}

	body, _ := json.Marshal(map[string]string{
		"agent_ref": *ref,
		"incident":  *incident,
		"operator":  *operator,
	})
	post("/policy/kill", body)
}

func cmdAudit(args []string) {
	fs := flag.NewFlagSet("audit", flag.ExitOnError)
	ref := fs.String("ref", "", "show only events for this agent ref")
	limit := fs.Int("limit", 100, "max events to show when -ref is not given")
	_ = fs.Parse(args)

	if *ref != "" {
		get("/agents/" + url.PathEscape(*ref) + "/audit")
		return
	}
	get(fmt.Sprintf("/audit?limit=%d", *limit))
}

func cmdCredentialIssue(args []string) {
	fs := flag.NewFlagSet("credential issue", flag.ExitOnError)
	ref := fs.String("ref", "", "agent ref to issue the credential for")
	kind := fs.String("kind", "api_key", "credential kind: api_key, oauth_token, or mtls_cert")
	ttl := fs.Duration("ttl", 0, "how long the credential is valid for, e.g. 24h; 0 means no expiry")
	operator := fs.String("operator", "niactl", "who is issuing this")
	_ = fs.Parse(args)

	if *ref == "" {
		fmt.Fprintln(os.Stderr, "credential issue: -ref is required")
		os.Exit(1)
	}

	body, _ := json.Marshal(map[string]any{
		"kind":        *kind,
		"ttl_seconds": int64(*ttl / time.Second),
		"operator":    *operator,
	})
	post("/agents/"+url.PathEscape(*ref)+"/credentials", body)
}

func cmdCredentialList(args []string) {
	fs := flag.NewFlagSet("credential list", flag.ExitOnError)
	ref := fs.String("ref", "", "agent ref to list credentials for")
	_ = fs.Parse(args)

	if *ref == "" {
		fmt.Fprintln(os.Stderr, "credential list: -ref is required")
		os.Exit(1)
	}
	get("/agents/" + url.PathEscape(*ref) + "/credentials")
}

func cmdCredentialRevoke(args []string) {
	fs := flag.NewFlagSet("credential revoke", flag.ExitOnError)
	id := fs.String("id", "", "credential id to revoke")
	reason := fs.String("reason", "", "why this credential is being revoked")
	operator := fs.String("operator", "niactl", "who is revoking this")
	_ = fs.Parse(args)

	if *id == "" {
		fmt.Fprintln(os.Stderr, "credential revoke: -id is required")
		os.Exit(1)
	}

	body, _ := json.Marshal(map[string]string{
		"revoked_by": *operator,
		"reason":     *reason,
	})
	post("/credentials/"+url.PathEscape(*id)+"/revoke", body)
}

func cmdToolRegister(args []string) {
	fs := flag.NewFlagSet("tool register", flag.ExitOnError)
	name := fs.String("name", "", "tool name")
	description := fs.String("description", "", "what this tool does")
	transport := fs.String("transport", "", "how the gateway reaches it: mcp, http, or grpc")
	risk := fs.String("risk", "read_only", "risk classification: read_only, write, or destructive")
	owner := fs.String("owner", "", "human or team accountable for this tool")
	_ = fs.Parse(args)

	if *name == "" {
		fmt.Fprintln(os.Stderr, "tool register: -name is required")
		os.Exit(1)
	}

	body, _ := json.Marshal(map[string]string{
		"name":        *name,
		"description": *description,
		"transport":   *transport,
		"risk_class":  *risk,
		"owner":       *owner,
	})
	post("/tools", body)
}

func cmdToolList(_ []string) {
	get("/tools")
}

func cmdToolGet(args []string) {
	fs := flag.NewFlagSet("tool get", flag.ExitOnError)
	name := fs.String("name", "", "tool name")
	_ = fs.Parse(args)

	if *name == "" {
		fmt.Fprintln(os.Stderr, "tool get: -name is required")
		os.Exit(1)
	}
	get("/tools/" + url.PathEscape(*name))
}

func cmdGraphAddNode(args []string) {
	fs := flag.NewFlagSet("graph add-node", flag.ExitOnError)
	id := fs.String("id", "", "node id, e.g. agent:billing-reconciler")
	kind := fs.String("kind", "", "node kind: human, agent, tool, or data")
	_ = fs.Parse(args)

	if *id == "" || *kind == "" {
		fmt.Fprintln(os.Stderr, "graph add-node: -id and -kind are required")
		os.Exit(1)
	}

	body, _ := json.Marshal(map[string]string{
		"id":   *id,
		"kind": *kind,
	})
	post("/graph/nodes", body)
}

func cmdGraphAddEdge(args []string) {
	fs := flag.NewFlagSet("graph add-edge", flag.ExitOnError)
	from := fs.String("from", "", "source node id")
	to := fs.String("to", "", "destination node id")
	kind := fs.String("kind", "", "edge kind: owns, delegates_to, trusts, member_of, grants, or bound_to")
	_ = fs.Parse(args)

	if *from == "" || *to == "" || *kind == "" {
		fmt.Fprintln(os.Stderr, "graph add-edge: -from, -to, and -kind are required")
		os.Exit(1)
	}

	body, _ := json.Marshal(map[string]string{
		"from": *from,
		"to":   *to,
		"kind": *kind,
	})
	post("/graph/edges", body)
}

func cmdGraphNeighbors(args []string) {
	fs := flag.NewFlagSet("graph neighbors", flag.ExitOnError)
	id := fs.String("id", "", "node id")
	kind := fs.String("kind", "", "edge kind to follow: owns, delegates_to, trusts, member_of, grants, or bound_to")
	_ = fs.Parse(args)

	if *id == "" || *kind == "" {
		fmt.Fprintln(os.Stderr, "graph neighbors: -id and -kind are required")
		os.Exit(1)
	}
	get("/graph/" + url.PathEscape(*id) + "/neighbors?kind=" + url.QueryEscape(*kind))
}

func cmdGraphReachable(args []string) {
	fs := flag.NewFlagSet("graph reachable", flag.ExitOnError)
	id := fs.String("id", "", "node id to start from")
	kinds := fs.String("kinds", "", "comma-separated edge kinds to follow; omitted means every edge kind")
	_ = fs.Parse(args)

	if *id == "" {
		fmt.Fprintln(os.Stderr, "graph reachable: -id is required")
		os.Exit(1)
	}
	path := "/graph/" + url.PathEscape(*id) + "/reachable"
	if *kinds != "" {
		path += "?kinds=" + url.QueryEscape(*kinds)
	}
	get(path)
}

func grantFlagSet(name string) (*flag.FlagSet, *string, *string, *string, *string, *string, *string) {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	ref := fs.String("ref", "", "agent ref")
	kind := fs.String("kind", "", "grant kind: api_group, endpoint, tool, or data")
	group := fs.String("group", "", "api_group grants: the group name")
	method := fs.String("method", "", "endpoint grants: the HTTP method")
	path := fs.String("path", "", "endpoint grants: the path")
	object := fs.String("object", "", "tool or data grants: the tool name or resource name")
	return fs, ref, kind, group, method, path, object
}

func grantRequestBody(kind, group, method, path, object, operator string) []byte {
	grant := map[string]string{"kind": kind}
	if group != "" {
		grant["group"] = group
	}
	if method != "" {
		grant["method"] = method
	}
	if path != "" {
		grant["path"] = path
	}
	if object != "" {
		grant["object"] = object
	}
	body, _ := json.Marshal(map[string]any{
		"grants":   []map[string]string{grant},
		"operator": operator,
	})
	return body
}

func cmdGrantWrite(args []string) {
	fs, ref, kind, group, method, path, object := grantFlagSet("grant write")
	operator := fs.String("operator", "niactl", "who is granting this")
	_ = fs.Parse(args)

	if *ref == "" || *kind == "" {
		fmt.Fprintln(os.Stderr, "grant write: -ref and -kind are required")
		os.Exit(1)
	}
	post("/agents/"+url.PathEscape(*ref)+"/grants", grantRequestBody(*kind, *group, *method, *path, *object, *operator))
}

func cmdGrantDelete(args []string) {
	fs, ref, kind, group, method, path, object := grantFlagSet("grant delete")
	operator := fs.String("operator", "niactl", "who is removing this")
	_ = fs.Parse(args)

	if *ref == "" || *kind == "" {
		fmt.Fprintln(os.Stderr, "grant delete: -ref and -kind are required")
		os.Exit(1)
	}
	del("/agents/"+url.PathEscape(*ref)+"/grants", grantRequestBody(*kind, *group, *method, *path, *object, *operator))
}

func cmdGrantList(args []string) {
	fs := flag.NewFlagSet("grant list", flag.ExitOnError)
	ref := fs.String("ref", "", "agent ref to list grants for")
	_ = fs.Parse(args)

	if *ref == "" {
		fmt.Fprintln(os.Stderr, "grant list: -ref is required")
		os.Exit(1)
	}
	get("/agents/" + url.PathEscape(*ref) + "/grants")
}

func cmdGatewayCall(args []string) {
	fs := flag.NewFlagSet("gateway call", flag.ExitOnError)
	ref := fs.String("ref", "", "agent ref making the call, sent as X-Agent-Ref")
	tool := fs.String("tool", "", "tool to call")
	arguments := fs.String("arguments", "", "JSON object of arguments to pass, e.g. {\"table\":\"customers\",\"columns\":[\"ssn\"]}")
	_ = fs.Parse(args)

	if *ref == "" || *tool == "" {
		fmt.Fprintln(os.Stderr, "gateway call: -ref and -tool are required")
		os.Exit(1)
	}

	resp, err := callGateway(*ref, *tool, *arguments)
	if err != nil {
		fmt.Fprintf(os.Stderr, "niactl: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	printResponse(resp)
}

// callGateway is the shared primitive both cmdGatewayCall and
// cmd/niactl's simulate command use: a real HTTP call to the gateway's
// tool-call endpoint, X-Agent-Ref set from ref, arguments (raw JSON
// object text, may be empty) wrapped in the {"arguments": ...} body
// shape cmd/gateway's toolCallRequest decodes. Returns the response
// unconsumed so callers can inspect status and body their own way
// rather than always printing it, simulate needs to interpret the
// result, not just show it.
func callGateway(ref, tool, arguments string) (*http.Response, error) {
	body := []byte(`{}`)
	if arguments != "" {
		var probe map[string]any
		if err := json.Unmarshal([]byte(arguments), &probe); err != nil {
			return nil, fmt.Errorf("-arguments must be a JSON object: %w", err)
		}
		wrapped, err := json.Marshal(map[string]any{"arguments": probe})
		if err != nil {
			return nil, err
		}
		body = wrapped
	}

	req, err := http.NewRequest(http.MethodPost, gatewayAddr()+"/tools/"+url.PathEscape(tool)+"/call", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Ref", ref)
	return http.DefaultClient.Do(req)
}

func del(path string, body []byte) {
	req, err := http.NewRequest(http.MethodDelete, apiAddr()+path, bytes.NewReader(body))
	if err != nil {
		fmt.Fprintf(os.Stderr, "niactl: %v\n", err)
		os.Exit(1)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "niactl: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	printResponse(resp)
}

func post(path string, body []byte) {
	resp, err := http.Post(apiAddr()+path, "application/json", bytes.NewReader(body))
	if err != nil {
		fmt.Fprintf(os.Stderr, "niactl: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	printResponse(resp)
}

func get(path string) {
	resp, err := http.Get(apiAddr() + path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "niactl: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	printResponse(resp)
}

func printResponse(resp *http.Response) {
	out, _ := io.ReadAll(resp.Body)
	fmt.Println(string(out))
	if resp.StatusCode >= 400 {
		os.Exit(1)
	}
}
