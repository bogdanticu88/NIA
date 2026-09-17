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
  niactl agent inspect -ref <agent_ref> [-audit-limit <n>]
  niactl risk -ref <agent_ref>
  niactl kill -ref <agent_ref> -incident <incident_id> [-operator <name>]
  niactl restore -ref <agent_ref> [-operator <name>]
  niactl audit [-ref <agent_ref>] [-limit <n>]
  niactl audit verify
  niactl credential issue -ref <agent_ref> -kind <api_key|oauth_token|mtls_cert> [-ttl <duration>]
  niactl credential list -ref <agent_ref>
  niactl credential revoke -id <credential_id> [-reason <reason>] [-operator <name>]
  niactl credential disable -id <credential_id> [-reason <reason>] [-operator <name>]
  niactl credential enable -id <credential_id> [-operator <name>]
  niactl credential rotate -id <credential_id> [-ttl <duration>] [-operator <name>]
  niactl tool register -name <tool_name> [-description <text>] [-transport <mcp|http|grpc>] [-risk <read_only|write|destructive>] [-owner <owner>]
  niactl tool list
  niactl tool get -name <tool_name>
  niactl graph add-node -id <node_id> -kind <human|agent|tool|data>
  niactl graph add-edge -from <node_id> -to <node_id> -kind <owns|delegates_to|trusts|member_of|grants|bound_to>
  niactl graph neighbors -id <node_id> -kind <edge_kind>
  niactl graph reachable -id <node_id> [-kinds <edge_kind,edge_kind,...>]
  niactl graph blast-radius -id <node_id> [-kinds <edge_kind,edge_kind,...>]
  niactl grant write -ref <agent_ref> -kind <api_group|endpoint|tool|data> [-group <g>] [-method <m>] [-path <p>] [-object <o>] [-operator <name>]
  niactl grant delete -ref <agent_ref> -kind <...> [-group|-method|-path|-object matching what was written] [-operator <name>]
  niactl grant list -ref <agent_ref>
  niactl gateway call -ref <agent_ref> -credential <id.secret> -tool <tool_name> [-arguments '<json object>']
  niactl simulate attack -scenario <agent-hijack>
  niactl incident list [-ref <agent_ref>] [-limit <n>]
  niactl incident get -id <incident_id>

audit with -ref shows everything recorded for that agent (registration,
grants, kills, every gateway decision), oldest first, the query an
incident review starts with. Without -ref it shows the n most recent
events across every agent (default 100). audit verify walks the entire
stored hash chain (see internal/audit/chain.go) and reports whether
it's intact: how many events were checked, how many predate chaining
and were skipped, and, if anything's wrong, exactly which events and
why, a modified event, a broken link where one was deleted, inserted,
or reordered. This proves the trail wasn't tampered with after the
fact, it does not by itself stop someone with direct database access
from rewriting both the events and the chain together, see that
package's own doc comment for the full reasoning.

agent inspect is the one command that composes several endpoints into a
single report: identity, credentials, grants, the most recent audit
events (most recent first, -audit-limit caps how many, default 10),
blast radius, and a best-effort look at the gateway's own risk view for
that agent, GET /risk/{ref}. The risk section is best-effort on purpose,
the gateway is a separate process and monitoring on it is opt-in (see
NIA_RISK_FLAG_AT and friends), an unreachable gateway or unconfigured
monitoring there is routine, not a failure of this command.

risk reads GET /risk/{ref} directly and prints the raw response: the
agent's current cumulative risk, the flag/revoke/kill thresholds it's
being compared against, and its most recent incidents on that gateway.
configured:false in the response means that gateway has no monitoring
set up at all, not that the agent has a clean history.

credential issue mints a real bearer credential now: the response's "secret"
field is shown exactly once, this command does not store it and cannot show
it again, save it immediately. Present it to the gateway as
"Authorization: Bearer <id>.<secret>", see cmd/gateway/authn.go. -ttl takes
a Go duration (24h, 30m); omitted or zero means no expiry. credential revoke
retires one key permanently, use kill instead when the agent itself is
compromised, that also cascades into revoking every active credential the
killed agent holds. credential disable is the reversible counterpart, an
administrative pause credential enable can undo, revoke cannot be undone.
credential rotate atomically revokes the named credential and issues a
replacement in one call, the old secret stops authenticating and the new one
starts in the same operation, no window where both or neither work, see
internal/credentials.Store.Rotate's doc comment.

restore clears the kill sentinel through internal/policy.Client.Restore. It
does not resurrect grants or credentials on its own, an operator must
separately call grant write with the intended grants and credential issue
for a fresh credential, restoring access is deliberately not "undo the
kill," see handleRestore's own doc comment in cmd/api/main.go.

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
an agent, a human or tool or data resource id for the rest. Registering an
agent or tool, issuing a credential, and writing a tool or data grant all
add their own nodes and edges automatically now, so add-node/add-edge is
mainly for a human node (nothing else creates those) or for adding
something ahead of when NIA would otherwise learn about it. graph
neighbors is one hop out along a single edge kind; graph reachable follows
edges transitively, the full node list, defaulting to every edge kind when
-kinds is omitted; graph blast-radius runs the same traversal but returns
counts by node kind, which reachable resources are classified sensitive or
critical (see internal/sensitivity, NIA_SENSITIVITY_RULES_PATH), and a
HIGH/MEDIUM/LOW severity call, see docs/ARCHITECTURE.md's identity graph
section for exactly how severity is decided. By design, not by omission:
the graph is historical and append-only, deleting a grant does not remove
the grants edge it added, there is no edge-removal operation and there
isn't going to be one, see internal/graph's own package doc comment.
Treat graph reachable/blast-radius as a superset of what's actually still
granted, useful for "what has this identity ever touched," never as a
live permission list, check niactl grant list for the current truth.

gateway call drives the gateway's own hot path directly, POST /tools/{tool}/call
with -credential presented as "Authorization: Bearer <id.secret>" (issue one
first with credential issue, -ref is for the human reading the output, the
gateway's default resolver, credentialResolver, does not read it at all, see
cmd/gateway/authn.go) and -arguments (a JSON object, optional) as the request
body's arguments field, the exact request an MCP-aware caller sends. Omitting
-credential only works against a gateway started with
NIA_GATEWAY_INSECURE_HEADER_AUTH=1, local dev only, see that variable's own
warning at gateway startup. This is what makes niactl simulate possible:
every step it prints is a real gateway call through this same path, not
printed output pretending to be one.

simulate attack drives a scripted, deterministic scenario end to end through
the real control-plane API and the real gateway: registers the scenario's
agent, registers its tools, writes its starting grants, issues the scenario
agent a real credential the same way credential issue does, then presents
that credential on every one of the scenario's sequence of gateway calls,
printing each one's real outcome, allowed, denied, and, once configured with
risk thresholds (see deployments/docker-compose.yml's comment on
NIA_RISK_FLAG_AT and friends),
watches containment actually fire and the agent's next request actually get
blocked. A re-run against an already-registered agent picks up where the
grants and tool catalog left off rather than failing, registration and
WriteGrants both tolerate "already exists," so running the same scenario
twice is safe, though a prior run's kill or accumulated risk carries
forward since there is no reset endpoint yet. Currently one scenario,
agent-hijack, see cmd/niactl/simulate.go for the full step-by-step script.

incident list/get read internal/incident's structured containment records,
not the audit trail, one record per flag/revoke/kill decision monitoring
actually made, with the risk value and signals that triggered it and the
cumulative total at that moment, see docs/ARCHITECTURE.md's "Attack
simulation" section for how this differs from audit's free-text incident
string. These talk to the gateway, not the control-plane API, because the
records are created there, alongside the monitor that decides to make
them; an empty list or a 404 on get most often just means monitoring was
never configured on that gateway (NIA_RISK_FLAG_AT and friends unset), not
that the request failed.

Every command talks to the control-plane API (NIA_API_URL, default http://localhost:8080)
except gateway call, simulate attack, incident list/get, and risk, which
talk to the gateway instead (NIA_GATEWAY_URL, default http://localhost:8081).
agent inspect talks to both: identity, credentials, grants, audit, and
blast radius come from the control-plane API, the risk section comes
from the gateway.`)
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
	case "agent":
		cmdAgent(os.Args[2:])
	case "risk":
		cmdRisk(os.Args[2:])
	case "kill":
		cmdKill(os.Args[2:])
	case "restore":
		cmdRestore(os.Args[2:])
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
	case "incident":
		cmdIncident(os.Args[2:])
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
	case "disable":
		cmdCredentialDisable(args[1:])
	case "enable":
		cmdCredentialEnable(args[1:])
	case "rotate":
		cmdCredentialRotate(args[1:])
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
	case "blast-radius":
		cmdGraphBlastRadius(args[1:])
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

func cmdIncident(args []string) {
	if len(args) < 1 {
		usage()
		os.Exit(1)
	}
	switch args[0] {
	case "list":
		cmdIncidentList(args[1:])
	case "get":
		cmdIncidentGet(args[1:])
	default:
		usage()
		os.Exit(1)
	}
}

func cmdIncidentList(args []string) {
	fs := flag.NewFlagSet("incident list", flag.ExitOnError)
	ref := fs.String("ref", "", "show only incidents for this agent ref, omitted means every agent")
	limit := fs.Int("limit", 0, "max incidents to show, 0 means everything on record")
	_ = fs.Parse(args)

	path := "/incidents"
	q := url.Values{}
	if *ref != "" {
		q.Set("ref", *ref)
	}
	if *limit > 0 {
		q.Set("limit", fmt.Sprintf("%d", *limit))
	}
	if enc := q.Encode(); enc != "" {
		path += "?" + enc
	}
	getGateway(path)
}

func cmdIncidentGet(args []string) {
	fs := flag.NewFlagSet("incident get", flag.ExitOnError)
	id := fs.String("id", "", "incident id, as returned by incident list")
	_ = fs.Parse(args)

	if *id == "" {
		fmt.Fprintln(os.Stderr, "incident get: -id is required")
		os.Exit(1)
	}
	getGateway("/incidents/" + url.PathEscape(*id))
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
	if len(args) > 0 && args[0] == "verify" {
		get("/audit/verify")
		return
	}

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

func cmdCredentialDisable(args []string) {
	fs := flag.NewFlagSet("credential disable", flag.ExitOnError)
	id := fs.String("id", "", "credential id to disable")
	reason := fs.String("reason", "", "why this credential is being paused")
	operator := fs.String("operator", "niactl", "who is disabling this")
	_ = fs.Parse(args)

	if *id == "" {
		fmt.Fprintln(os.Stderr, "credential disable: -id is required")
		os.Exit(1)
	}

	body, _ := json.Marshal(map[string]string{
		"disabled_by": *operator,
		"reason":      *reason,
	})
	post("/credentials/"+url.PathEscape(*id)+"/disable", body)
}

func cmdCredentialEnable(args []string) {
	fs := flag.NewFlagSet("credential enable", flag.ExitOnError)
	id := fs.String("id", "", "credential id to re-enable")
	operator := fs.String("operator", "niactl", "who is enabling this")
	_ = fs.Parse(args)

	if *id == "" {
		fmt.Fprintln(os.Stderr, "credential enable: -id is required")
		os.Exit(1)
	}

	body, _ := json.Marshal(map[string]string{"enabled_by": *operator})
	post("/credentials/"+url.PathEscape(*id)+"/enable", body)
}

func cmdCredentialRotate(args []string) {
	fs := flag.NewFlagSet("credential rotate", flag.ExitOnError)
	id := fs.String("id", "", "credential id to rotate")
	ttl := fs.Duration("ttl", 0, "how long the replacement is valid for, e.g. 24h; 0 means no expiry")
	operator := fs.String("operator", "niactl", "who is rotating this")
	_ = fs.Parse(args)

	if *id == "" {
		fmt.Fprintln(os.Stderr, "credential rotate: -id is required")
		os.Exit(1)
	}

	body, _ := json.Marshal(map[string]any{
		"rotated_by":  *operator,
		"ttl_seconds": int64(*ttl / time.Second),
	})
	post("/credentials/"+url.PathEscape(*id)+"/rotate", body)
}

func cmdRestore(args []string) {
	fs := flag.NewFlagSet("restore", flag.ExitOnError)
	ref := fs.String("ref", "", "agent ref to restore")
	operator := fs.String("operator", "niactl", "who is restoring this agent")
	_ = fs.Parse(args)

	if *ref == "" {
		fmt.Fprintln(os.Stderr, "restore: -ref is required")
		os.Exit(1)
	}

	body, _ := json.Marshal(map[string]string{
		"agent_ref": *ref,
		"operator":  *operator,
	})
	post("/policy/restore", body)
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

func cmdGraphBlastRadius(args []string) {
	fs := flag.NewFlagSet("graph blast-radius", flag.ExitOnError)
	id := fs.String("id", "", "node id to start from")
	kinds := fs.String("kinds", "", "comma-separated edge kinds to follow; omitted means every edge kind")
	_ = fs.Parse(args)

	if *id == "" {
		fmt.Fprintln(os.Stderr, "graph blast-radius: -id is required")
		os.Exit(1)
	}
	path := "/graph/" + url.PathEscape(*id) + "/blast-radius"
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
	ref := fs.String("ref", "", "agent ref making the call, informational only, credentialResolver does not read it, see -credential")
	credential := fs.String("credential", "", "bearer credential as id.secret, from credential issue's response; sent as Authorization: Bearer <credential>")
	tool := fs.String("tool", "", "tool to call")
	arguments := fs.String("arguments", "", "JSON object of arguments to pass, e.g. {\"table\":\"customers\",\"columns\":[\"ssn\"]}")
	_ = fs.Parse(args)

	if *ref == "" || *tool == "" {
		fmt.Fprintln(os.Stderr, "gateway call: -ref and -tool are required")
		os.Exit(1)
	}

	resp, err := callGateway(*ref, *credential, *tool, *arguments)
	if err != nil {
		fmt.Fprintf(os.Stderr, "niactl: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	printResponse(resp)
}

// callGateway is the shared primitive both cmdGatewayCall and
// cmd/niactl's simulate command use: a real HTTP call to the gateway's
// tool-call endpoint, arguments (raw JSON object text, may be empty)
// wrapped in the {"arguments": ...} body shape cmd/gateway's
// toolCallRequest decodes. Returns the response unconsumed so callers
// can inspect status and body their own way rather than always
// printing it, simulate needs to interpret the result, not just show
// it.
//
// credential is presented as "Authorization: Bearer <credential>",
// cmd/gateway's default resolver, credentialResolver, is what actually
// authenticates the call, see cmd/gateway/authn.go. X-Agent-Ref is
// still sent alongside it, for a human reading a request log or
// running against a gateway started with
// NIA_GATEWAY_INSECURE_HEADER_AUTH=1 (headerResolver, local dev only),
// but credentialResolver itself never reads that header, an empty
// credential against the default gateway gets a 401, not a fallback.
func callGateway(ref, credential, tool, arguments string) (*http.Response, error) {
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
	if credential != "" {
		req.Header.Set("Authorization", "Bearer "+credential)
	}
	return http.DefaultClient.Do(req)
}

// operatorToken is NIA_OPERATOR_TOKEN, distinct from cmd/api's own
// NIA_OPERATOR_TOKENS_PATH (the server-side file naming which tokens
// are valid and who each belongs to): this is the one token this
// invocation of niactl presents. Empty when unset, which is the
// correct default against a cmd/api that has no NIA_OPERATOR_TOKENS_PATH
// of its own, operatorAuthMiddleware never runs there and no
// Authorization header is expected, see cmd/api/opauth.go. Against a
// cmd/api that does have operator auth configured, every del/post/get
// call below would otherwise get a 401, same failure shape
// callGateway's own credential parameter closes for the gateway.
func operatorToken() string {
	return os.Getenv("NIA_OPERATOR_TOKEN")
}

func setOperatorAuth(req *http.Request) {
	if tok := operatorToken(); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
}

func del(path string, body []byte) {
	req, err := http.NewRequest(http.MethodDelete, apiAddr()+path, bytes.NewReader(body))
	if err != nil {
		fmt.Fprintf(os.Stderr, "niactl: %v\n", err)
		os.Exit(1)
	}
	req.Header.Set("Content-Type", "application/json")
	setOperatorAuth(req)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "niactl: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	printResponse(resp)
}

func post(path string, body []byte) {
	req, err := http.NewRequest(http.MethodPost, apiAddr()+path, bytes.NewReader(body))
	if err != nil {
		fmt.Fprintf(os.Stderr, "niactl: %v\n", err)
		os.Exit(1)
	}
	req.Header.Set("Content-Type", "application/json")
	setOperatorAuth(req)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "niactl: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	printResponse(resp)
}

func get(path string) {
	req, err := http.NewRequest(http.MethodGet, apiAddr()+path, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "niactl: %v\n", err)
		os.Exit(1)
	}
	setOperatorAuth(req)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "niactl: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	printResponse(resp)
}

// getGateway is get's twin for the handful of read endpoints that live
// on the gateway rather than the control-plane API, today just
// /incidents and /incidents/{id}, see internal/incident's own doc
// comment for why those records are created (and so read back) from
// cmd/gateway's own process rather than cmd/api's.
func getGateway(path string) {
	resp, err := http.Get(gatewayAddr() + path)
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
