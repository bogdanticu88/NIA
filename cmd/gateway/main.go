// cmd/gateway is the Agent/MCP Gateway: the hot path. Every inbound
// call from an agent to a tool or data resource passes through here.
// The gateway does exactly three things, in order: resolve the caller
// to a canonical agent identity, ask the policy client for a live
// authorization decision, and forward or block. It never caches an
// allow, and it never makes an authorization decision itself, that
// stays in internal/policy (Tessera/OpenFGA), so the gateway can be
// swapped out or scaled horizontally without the authorization model
// moving with it.
//
// MCP integration lives here: an MCP tool-call request is just another
// inbound request that needs an identity resolved and a grant checked
// before it's forwarded to the underlying tool. When
// NIA_GATEWAY_DOWNSTREAM_URL is set, an authorized call actually
// reaches a real downstream tool/MCP server, gets its response
// inspected for anything security-relevant, and that response, not a
// stand-in, is what the agent gets back, see forward.go. Unset, the
// gateway still makes and audits the exact same decision, it just
// stops there and returns its own response, the same behavior every
// gateway before this pass had. Forwarding is strictly the last step:
// identity, credential state, kill state, tool and resource
// authorization, and risk scoring all run and can all still reject the
// call first, there is no second, unguarded route to a downstream
// tool, handleToolCall is the only place Forward is ever called from.
//
// When NIA_TOOLS_API_URL is set, resolve -> check grows a step in
// front: look the tool up in cmd/api's catalog first, and reject
// outright if nobody registered it. That lookup goes over HTTP back to
// cmd/api rather than a second shared store, the same tradeoff
// internal/audit made before PostgresSink existed, except here there's
// no PostgresSink equivalent planned, a tool's existence changes rarely
// compared to the hot path's actual bottleneck, the policy check
// itself, so a cheap HTTP round trip to the one process that already
// owns the catalog is the whole answer, not a stopgap. Unset, this step
// is skipped entirely and the gateway's original tool-name-only
// behavior is unchanged, this is additive, nothing that worked before
// this existed stops working.
//
// A tool-level allow is not the end of the decision either. When
// NIA_GATEWAY_RESOURCE_RULES_PATH is set, the gateway decodes the call's
// arguments (see toolCallRequest) and asks an ArgumentResourcePolicy
// which resource object names they touch, "customers.ssn" out of a
// database.query call naming a table and a column, see resources.go.
// Any resource classified at sensitivity.Sensitive or above (via
// NIA_SENSITIVITY_RULES_PATH, see internal/sensitivity) needs its own
// policy.GrantForData grant, checked the same way the tool-level grant
// is, denied and audited separately if it's missing. This is the
// Agent+Tool+Action+Resource decision, not just Agent+Tool: an agent
// can be authorized to call database.query and still not be authorized
// to retrieve a column an operator has flagged as sensitive. Both env
// vars unset (the default) skips this entirely, same additive posture
// as the catalog check, nothing that worked before this existed stops
// working, and an agent granted a resource nobody bothered to classify
// stays unaffected either way, classification is opt-in per resource.
//
// Every decision this makes, allow, deny, or a check that errored
// outright, also goes to internal/audit, that's the second half of what
// audit's package doc means by "aggregates events from the gateway."
//
// An allowed call doesn't stop there either. When NIA_RISK_FLAG_AT,
// NIA_RISK_REVOKE_AT, or NIA_RISK_KILL_AT is set, every allowed call is
// scored (internal/risk.HistoryScorer, sharing the same tool catalog
// reader the enforcement step above uses) and handed to
// internal/monitoring, which flags, revokes the agent's credentials, or
// kills it outright if the score crosses a threshold. None of the
// three set means monitoring is skipped entirely, same additive
// posture as the catalog check: nothing that worked before this
// existed stops working. A monitoring failure (the kill or revoke
// itself erroring) is audited and logged, not turned into a failed
// response, the call itself was already legitimately authorized before
// monitoring ever ran, see risk.CallContext's own doc comment.
//
// Every flag, revoke, or kill decision also gets a structured
// internal/incident record, not just an audit line, readable back
// through GET /incidents and GET /incidents/{id}. See that package's
// own doc comment for why it's a separate thing from internal/audit.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/bogdanticu88/nia/internal/audit"
	"github.com/bogdanticu88/nia/internal/credentials"
	"github.com/bogdanticu88/nia/internal/identity"
	"github.com/bogdanticu88/nia/internal/incident"
	"github.com/bogdanticu88/nia/internal/metrics"
	"github.com/bogdanticu88/nia/internal/monitoring"
	"github.com/bogdanticu88/nia/internal/opauth"
	"github.com/bogdanticu88/nia/internal/policy"
	"github.com/bogdanticu88/nia/internal/ratelimit"
	"github.com/bogdanticu88/nia/internal/registry/tools"
	"github.com/bogdanticu88/nia/internal/risk"
	"github.com/bogdanticu88/nia/internal/sensitivity"
	niahttp "github.com/bogdanticu88/nia/internal/transport/http"
)

// headerResolver trusts a single header carrying the agent ref outright,
// no credential, no proof of possession. This used to be the gateway's
// only Resolver and its default. As of the security hardening pass it
// is neither: credentialResolver (authn.go) is the default, this stays
// only for explicit, opt-in, clearly-labeled insecure local use, see
// NIA_GATEWAY_INSECURE_HEADER_AUTH in main() below. Anyone who can set
// an HTTP header becomes whatever agent they name, this is exactly the
// weakness docs/THREAT_MODEL.md's original threats 1 and 2 both reduced
// to, kept here for local dev convenience and for tests that don't want
// to mint a credential, never for anything reachable by an untrusted
// caller.
type headerResolver struct {
	headerName string
}

func (h headerResolver) Resolve(_ context.Context, rc identity.ResolveContext) (*identity.ResolvedIdentity, error) {
	ref, ok := rc.Headers[h.headerName]
	if !ok || ref == "" {
		return nil, nil
	}
	return &identity.ResolvedIdentity{Ref: ref, Assurance: identity.AssuranceWeak}, nil
}

type gateway struct {
	resolver       identity.Resolver
	pol            policy.Client
	toolCat        tools.Reader           // nil means catalog enforcement is not configured, see FromEnvReader
	resourcePolicy ArgumentResourcePolicy // nil means argument inspection is not configured, see resourcePolicyFromEnv
	sensitive      sensitivity.Classifier // nil means every resource is treated as Public, no data-grant check runs
	scorer         risk.Scorer            // nil means monitoring is not configured, kept nil together with monitor
	monitor        *monitoring.Monitor    // nil means monitoring is not configured, see monitoring.ThresholdsFromEnv
	incidents      incident.Store         // nil unless monitor is also configured, see main(); GET /incidents and GET /incidents/{id} read this directly
	forwarder      Forwarder              // nil means downstream forwarding is not configured, see forward.go and forwarderFromEnv
	// opStore authenticates the operator-facing read endpoints below
	// (GET /incidents, GET /incidents/{id}, GET /risk/{ref}). It is
	// unrelated to how a tool call authenticates: an agent presents its
	// own credential to POST /tools/{tool}/call and never an operator
	// token, see authn.go. nil only when NIA_ALLOW_UNAUTHENTICATED=1
	// was set deliberately, see opauth.FromEnvEnforced.
	opStore opauth.Store
	// clientLimiter bounds requests per client address, in front of
	// everything including credential verification. agentLimiter bounds
	// what one authenticated agent can do, applied inside
	// handleToolCall once identity is known, because that is the first
	// moment the agent's ref exists. The two are not redundant: one
	// agent can call from many addresses, and one address can present
	// many agents' credentials.
	// mcpDownstream is the MCP server this gateway proxies to, nil when
	// NIA_GATEWAY_MCP_DOWNSTREAM_URL is unset, in which case /mcp is not
	// served at all. Separate from forwarder: that one is the plain JSON
	// downstream, this one speaks MCP, and a deployment can have either,
	// both or neither.
	mcpDownstream  *mcpDownstream
	clientLimiter  *ratelimit.Limiter
	agentLimiter   *ratelimit.Limiter
	trustForwarded bool
	auditLog       audit.Sink
	metrics        *gatewayMetrics
	metricsReg     *metrics.Registry // handleFunc target for GET /metrics
}

// gatewayMetrics is every counter cmd/gateway exposes over GET /metrics.
// requests is the hot-path counter, one Inc per handleToolCall outcome,
// named to match the audit actions the same branches already write
// (see the "gateway." prefixed actions throughout this file) so a
// metric and an audit event describe the same decision two different
// ways. monitoringActions counts only an actual containment response
// (flag, revoke, kill), not every scored call, "how often did
// monitoring do something" is the useful aggregate, "how often was a
// call scored" is nia_gateway_requests_total{outcome="allowed"} already,
// every allowed call gets scored when monitoring is configured.
// auditWriteFailures mirrors cmd/api's counter of the same name, this
// process keeps its own audit sink and its own failure count.
type gatewayMetrics struct {
	requests           *metrics.Counter // outcome: allowed|denied_tool|denied_resource|unknown_tool|tool_lookup_error|check_error|resolve_error|unresolved|downstream_ok|downstream_client_error|downstream_server_error|downstream_unreachable|downstream_ungranted_field
	monitoringActions  *metrics.Counter // action: flag|revoke|kill
	auditWriteFailures *metrics.Counter // no labels
	rateLimited        *metrics.Counter // scope: client|agent
}

func newGatewayMetrics(reg *metrics.Registry) *gatewayMetrics {
	return &gatewayMetrics{
		requests:           reg.NewCounter("nia_gateway_requests_total", "tool-call requests by outcome", "outcome"),
		monitoringActions:  reg.NewCounter("nia_monitoring_actions_total", "monitoring responses to a scored call by action", "action"),
		auditWriteFailures: reg.NewCounter("nia_audit_write_failures_total", "audit trail append failures, fail-open by design, see docs/SECURITY_INVARIANTS.md invariant 8"),
		rateLimited:        reg.NewCounter("nia_rate_limited_total", "requests refused with 429 by a rate limiter, by which limiter refused them", "scope"),
	}
}

// toolCallRequest is the request body handleToolCall decodes.
// Arguments is optional and opaque to the gateway itself, its shape is
// whatever the tool underneath expects; the only thing this handler
// does with it is hand it to resourcePolicy, when one is configured, to
// find out what resources it names. An empty or absent body is not an
// error, most tools take no arguments worth inspecting, and every call
// site that predates this field still works unchanged.
type toolCallRequest struct {
	Arguments map[string]any `json:"arguments"`
}

// handleToolCall is the shape every tool/MCP call goes through:
// resolve -> check -> inspect arguments -> forward. It's intentionally
// the only enforcement point; there is no second place in the codebase
// that decides whether a call is allowed.
func (g *gateway) handleToolCall(w http.ResponseWriter, r *http.Request) {
	resolved, err := g.resolver.Resolve(r.Context(), resolveContextFor(r))
	if err != nil {
		g.metrics.requests.Inc("resolve_error")
		niahttp.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if resolved == nil {
		g.metrics.requests.Inc("unresolved")
		niahttp.WriteError(w, http.StatusUnauthorized, "could not resolve caller identity")
		return
	}

	tool := r.PathValue("tool")
	ctx := r.Context()

	var body toolCallRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
		niahttp.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// The whole security pipeline, shared with the MCP transport so the
	// two front doors cannot drift apart, see decision.go.
	decision := g.decideToolCall(ctx, resolved, tool, body.Arguments)
	if !decision.Allowed {
		if decision.Outcome == outcomeRateLimited {
			w.Header().Set("Retry-After", "1")
		}
		niahttp.WriteError(w, decision.HTTPStatus(), decision.Message)
		return
	}

	resp := map[string]any{
		"agent":  resolved.Ref,
		"tool":   tool,
		"status": "allowed",
	}
	if decision.Risk != nil {
		resp["risk"] = *decision.Risk
	}

	// Everything above this point is the decision: identity, credential
	// state, kill state (both inside g.resolver.Resolve, see authn.go),
	// tool-level and resource-level authorization, risk scoring. Nothing
	// below this line can turn a denial into an allow, forwarding only
	// happens after every one of those gates has already said yes, and
	// there is no second route into a downstream tool that skips them,
	// handleToolCall is the only handler that ever calls Forward.
	//
	// g.forwarder == nil is the pre-forwarding default: the gateway
	// proves the decision and stops there, the same stub response this
	// handler always returned. Set NIA_GATEWAY_DOWNSTREAM_URL to make
	// this an actual enforcement proxy instead of a decision service,
	// see forward.go.
	if g.forwarder == nil {
		niahttp.WriteJSON(w, http.StatusOK, resp)
		return
	}

	result, err := g.forwarder.Forward(ctx, tool, body.Arguments)
	if err != nil {
		// The call was authorized, the downstream itself just isn't
		// reachable, a different failure mode from anything decided
		// above and worth its own outcome and its own audit action so
		// an incident review can tell "we said yes and couldn't deliver
		// it" apart from every "we said no" branch earlier in this
		// function.
		g.metrics.requests.Inc("downstream_unreachable")
		g.audit(ctx, "gateway.downstream_unreachable", resolved.Ref, fmt.Sprintf("tool=%s credential=%s err=%v", tool, resolved.CredentialID, err))
		niahttp.WriteError(w, http.StatusBadGateway, "downstream tool call failed")
		return
	}

	g.inspectAndAuditDownstream(ctx, resolved.Ref, tool, resolved.CredentialID, result)

	resp["downstream_status"] = result.StatusCode
	resp["downstream_duration_ms"] = result.Duration.Milliseconds()
	if len(result.Body) > 0 {
		var decoded any
		if err := json.Unmarshal(result.Body, &decoded); err == nil {
			resp["result"] = decoded
		} else {
			// Not every real tool answers with JSON, this is a proxy,
			// not a validator, an opaque body still reaches the agent
			// rather than being dropped because it didn't parse.
			resp["result"] = string(result.Body)
		}
	}

	// Mirror the downstream's own status when it answered with
	// something other than success: an agent calling through the
	// gateway should see the same failure it would see calling the tool
	// directly, the gateway's job was authorization, not hiding that
	// the tool itself said no or broke.
	status := http.StatusOK
	if result.StatusCode != 0 {
		status = result.StatusCode
	}
	niahttp.WriteJSON(w, status, resp)
}

// inspectAndAuditDownstream looks at what a downstream tool actually
// returned for anything worth a security review noticing on its own,
// separate from whether the call was authorized to happen at all. This
// is deliberately a small, named set of checks, not a content scanner:
// a downstream response body is arbitrary tool output, NIA has no
// general way to know what in it matters, what it can do honestly is
// flag the shapes that are always worth a second look regardless of
// which tool produced them.
func (g *gateway) inspectAndAuditDownstream(ctx context.Context, agentRef, tool, credentialID string, result ForwardResult) {
	detail := fmt.Sprintf("tool=%s credential=%s status=%d duration_ms=%d bytes=%d", tool, credentialID, result.StatusCode, result.Duration.Milliseconds(), len(result.Body))

	switch {
	case result.StatusCode >= 500:
		g.metrics.requests.Inc("downstream_server_error")
		g.audit(ctx, "gateway.downstream_error", agentRef, detail)
	case result.StatusCode >= 400:
		g.metrics.requests.Inc("downstream_client_error")
		g.audit(ctx, "gateway.downstream_rejected", agentRef, detail)
	default:
		g.metrics.requests.Inc("downstream_ok")
		g.audit(ctx, "gateway.downstream_ok", agentRef, detail)
	}

	if len(result.Body) >= maxDownstreamResponseBytes {
		// The response was cut off at the read cap, worth its own audit
		// line: a caller reading "result" back later has no other way
		// to know the body they're looking at is partial, and a
		// downstream suddenly returning far more data than usual is a
		// signal on its own, a possible sign of a bulk data pull
		// through a tool that isn't normally used that way.
		g.audit(ctx, "gateway.downstream_response_truncated", agentRef, detail)
	}

	if msg, ok := downstreamReportedError(result.Body); ok {
		g.audit(ctx, "gateway.downstream_reported_error", agentRef, detail+fmt.Sprintf(" error=%q", msg))
	}

	g.inspectResponseFields(ctx, agentRef, tool, credentialID, detail, result.Body)
}

// inspectResponseFields is the check that looks at what actually came
// back rather than only at whether the call was allowed to happen.
//
// The gap it closes: the request-side check (resources.go) decides what
// a call is asking for from its arguments, and an agent granted
// database.query on a table it is entitled to can still receive a
// column nobody granted, because the downstream decides what to put in
// the response. Before this, that response reached the agent and the
// only thing the gateway recorded was that the call succeeded.
//
// Deliberately audit and score, not block. By the time this runs the
// downstream has already produced the data and the response is on its
// way back, so "deny" here would be theatre: the tool has already read
// it. What this can honestly do is make it visible, attribute it, and
// feed it into the risk total that does have teeth, so an agent pulling
// fields it was never granted accumulates toward containment. Actually
// preventing it means either declaring the resource up front so the
// request-side data-grant check refuses the call, which already works
// today, or filtering the response, which would mean NIA deciding what
// an agent is allowed to see field by field and is a much larger
// design than this.
func (g *gateway) inspectResponseFields(ctx context.Context, agentRef, tool, credentialID, detail string, body []byte) {
	if g.sensitive == nil || len(body) == 0 {
		return
	}
	fields := sensitiveResponseFields(body, g.sensitive)
	if len(fields) == 0 {
		return
	}

	// Split by whether the agent actually holds a data grant for the
	// field. Both are worth recording, for different reasons: a granted
	// sensitive field in a response is ordinary but worth having in the
	// trail during an investigation, an ungranted one is the finding.
	var granted, ungranted []string
	for _, field := range fields {
		allowed, err := g.pol.Check(ctx, agentRef, policy.GrantForData(field))
		if err != nil {
			// Same posture the rest of this function takes: the call is
			// already done, an unanswerable check is recorded rather
			// than turned into a failure, and it is not counted as a
			// finding because nobody knows whether it is one.
			g.audit(ctx, "gateway.downstream_field_check_error", agentRef, detail+fmt.Sprintf(" field=%s err=%v", field, err))
			continue
		}
		if allowed {
			granted = append(granted, field)
			continue
		}
		ungranted = append(ungranted, field)
	}

	if len(granted) > 0 {
		g.audit(ctx, "gateway.downstream_sensitive_fields", agentRef, detail+fmt.Sprintf(" granted_fields=%s", formatFieldList(granted)))
	}
	if len(ungranted) == 0 {
		return
	}

	g.metrics.requests.Inc("downstream_ungranted_field")
	g.audit(ctx, "gateway.downstream_ungranted_fields", agentRef,
		detail+fmt.Sprintf(" ungranted_fields=%s", formatFieldList(ungranted)))

	// Feed it into the risk total, which is the part with consequences.
	// Scored separately from the call itself so an operator reading an
	// incident can see the response, not just the request, was what
	// pushed the agent over.
	if g.monitor != nil && g.scorer != nil {
		g.observeResponse(ctx, agentRef, tool, ungranted)
	}
}

// downstreamReportedError looks for a top-level "error" string field in
// a JSON response body, the same shape internal/transport/http.WriteError
// already produces, so a downstream tool built on this codebase's own
// conventions (or anything else that answers errors the same way)
// surfaces its own failures into the audit trail even when its HTTP
// status code was a plain 200. Anything else, a non-JSON body, no such
// field, an empty one, is not treated as an error, this is a narrow,
// specific check, not general content inspection.
func downstreamReportedError(body []byte) (string, bool) {
	var parsed struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", false
	}
	if parsed.Error == "" {
		return "", false
	}
	return parsed.Error, true
}

// riskInfo is the risk block handleToolCall attaches to an allowed
// call's response when monitoring is configured. It's the same number
// and reasoning internal/monitoring itself acted on, not a second
// opinion computed for display purposes; Cumulative and Action are
// what actually decided whether anything got enforced, Value and
// Signals are this one call's own contribution to that total.
type riskInfo struct {
	Value      float64           `json:"value"`
	Signals    []riskSignal      `json:"signals"`
	Cumulative float64           `json:"cumulative"`
	Action     monitoring.Action `json:"action"`
}

type riskSignal struct {
	Name   string  `json:"name"`
	Weight float64 `json:"weight"`
}

// observe scores an already-allowed call and lets internal/monitoring
// act on it. Errors here are audited and logged, not turned into a
// failed response: the call was legitimately authorized before this
// ever ran, a monitoring-side failure (the kill or revoke call itself
// erroring) is a separate incident from whether this request should
// have gone through. The bool return is whether scoring succeeded at
// all, a scoring error means there is no risk data worth attaching to
// the response, not that the call should look unscored versus scored
// zero.
// observeResponse scores the fields a downstream actually returned that
// the agent holds no data grant for, and hands the result to the same
// monitor the request-side scoring uses, so a response-side finding can
// cross the same thresholds and trigger the same containment.
//
// It scores through the same CallContext.Resources path the request side
// uses rather than inventing a second signal type: from internal/risk's
// point of view "this call touched customers.ssn" is the same fact
// whether the arguments named it or the response carried it, and the
// weighting for a sensitive or critical resource is already tuned for
// exactly that. What differs is the audit trail, where the two arrive
// under different actions.
//
// Best effort, like the rest of the post-decision path: the call has
// already happened, so a scoring failure is recorded and does not fail
// the response.
func (g *gateway) observeResponse(ctx context.Context, agentRef, tool string, ungranted []string) {
	score, err := g.scorer.Score(ctx, risk.CallContext{AgentRef: agentRef, Tool: tool, At: time.Now(), Resources: ungranted})
	if err != nil {
		g.audit(ctx, "gateway.scoring_error", agentRef, fmt.Sprintf("tool=%s phase=response err=%v", tool, err))
		return
	}
	incidentRef := fmt.Sprintf("auto-response-%d", time.Now().UnixNano())
	action, err := g.monitor.Observe(ctx, score, incidentRef)
	if err != nil {
		g.audit(ctx, "gateway.monitoring_error", agentRef, fmt.Sprintf("tool=%s phase=response incident=%s err=%v", tool, incidentRef, err))
		return
	}
	if action != monitoring.ActionNone {
		g.metrics.monitoringActions.Inc(string(action))
	}
}

func (g *gateway) observe(ctx context.Context, agentRef, tool string, resources []string) (riskInfo, bool) {
	score, err := g.scorer.Score(ctx, risk.CallContext{AgentRef: agentRef, Tool: tool, At: time.Now(), Resources: resources})
	if err != nil {
		g.audit(ctx, "gateway.scoring_error", agentRef, fmt.Sprintf("tool=%s err=%v", tool, err))
		log.Printf("nia-gateway: scoring failed for %s on %s: %v", agentRef, tool, err)
		return riskInfo{}, false
	}

	incident := fmt.Sprintf("auto-risk-%d", time.Now().UnixNano())
	action, err := g.monitor.Observe(ctx, score, incident)
	if err != nil {
		g.audit(ctx, "gateway.monitoring_error", agentRef, fmt.Sprintf("tool=%s incident=%s err=%v", tool, incident, err))
		log.Printf("nia-gateway: monitoring action failed for %s on %s: %v", agentRef, tool, err)
	}
	if action != monitoring.ActionNone {
		g.metrics.monitoringActions.Inc(string(action))
	}

	signals := make([]riskSignal, 0, len(score.Signals))
	for _, s := range score.Signals {
		signals = append(signals, riskSignal{Name: s.Name, Weight: s.Weight})
	}
	// A read failure here is display-only, not a decision: Observe
	// above already decided and acted on the authoritative total it got
	// straight out of the risk store's own Accumulate call, this is
	// only fetching that same number again to put in the response.
	// Fails open to 0 with a log line, same posture as a scoring
	// failure a few lines up, never treated as "this agent has no risk
	// history."
	cumulative, err := g.monitor.CumulativeRisk(ctx, agentRef)
	if err != nil {
		log.Printf("nia-gateway: reading cumulative risk failed for %s: %v", agentRef, err)
	}
	return riskInfo{
		Value:      score.Value,
		Signals:    signals,
		Cumulative: cumulative,
		Action:     action,
	}, true
}

// audit records one gateway decision. It never resolved caller
// identity is not itself audited here, an event with no AgentRef has
// no subject to attach it to, that failure mode shows up in the
// gateway's own logs instead. A failed Append is logged rather than
// silently dropped, on a security control plane a decision that didn't
// make it into the trail is worth knowing about even though there is
// nothing useful this handler can do about it mid-request.
func (g *gateway) audit(ctx context.Context, action, agentRef, detail string) {
	if g.auditLog == nil {
		return
	}
	if err := g.auditLog.Append(ctx, audit.Event{
		Action:   action,
		AgentRef: agentRef,
		Operator: agentRef,
		Detail:   detail,
		At:       time.Now(),
	}); err != nil {
		g.metrics.auditWriteFailures.Inc()
		log.Printf("nia-gateway: audit append failed: %v", err)
	}
}

// handleListIncidents and handleGetIncident are the read side of
// internal/incident: structured containment records, one per
// flag/revoke/kill decision internal/monitoring actually made, see that
// package's own doc comment for how this differs from grepping
// internal/audit for events that happen to share an incident string.
// Both are gateway-local, not cmd/api, because the records themselves
// are created here, in this process, alongside the Monitor that decides
// to make them, see this file's own package doc comment on why
// monitoring lives on the gateway side at all. When incidents is nil,
// monitoring itself isn't configured, so there is nothing to have
// recorded, list returns an empty array and get returns 404 rather than
// either one pretending the endpoint doesn't exist.
func (g *gateway) handleListIncidents(w http.ResponseWriter, r *http.Request) {
	if g.incidents == nil {
		niahttp.WriteJSON(w, http.StatusOK, []incident.Incident{})
		return
	}
	agentRef := r.URL.Query().Get("ref")
	limit := 0
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			limit = n
		}
	}
	incidents, err := g.incidents.List(r.Context(), agentRef, limit)
	if err != nil {
		niahttp.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	niahttp.WriteJSON(w, http.StatusOK, incidents)
}

func (g *gateway) handleGetIncident(w http.ResponseWriter, r *http.Request) {
	if g.incidents == nil {
		niahttp.WriteError(w, http.StatusNotFound, "incident not found")
		return
	}
	in, err := g.incidents.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, incident.ErrNotFound) {
			niahttp.WriteError(w, http.StatusNotFound, "incident not found")
			return
		}
		niahttp.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	niahttp.WriteJSON(w, http.StatusOK, in)
}

// riskReport is what GET /risk/{ref} returns: the same running total and
// thresholds internal/monitoring.Monitor is itself comparing on every
// call, plus a page of that agent's most recent incident records so a
// caller (niactl risk, an operator paging through an investigation)
// doesn't have to separately query GET /incidents?ref=... and cross
// reference the cumulative number by hand. Configured is false when
// this gateway has no Monitor at all (see monitoring.ThresholdsFromEnv),
// the honest way to say "there is nothing to report" rather than
// returning a zero Cumulative that looks identical to an agent that's
// actually never done anything risky.
type riskReport struct {
	AgentRef   string               `json:"agent_ref"`
	Configured bool                 `json:"configured"`
	Cumulative float64              `json:"cumulative,omitempty"`
	Thresholds monitoring.Threshold `json:"thresholds,omitempty"`
	Incidents  []incident.Incident  `json:"incidents,omitempty"`
}

// riskReportIncidentLimit bounds how many recent incidents handleRisk
// returns inline, the same reasoning cmd/api's handleRecentAudit bounds
// its own default limit: a caller wants a recent picture, not a full
// table scan through one HTTP response.
const riskReportIncidentLimit = 20

func (g *gateway) handleRisk(w http.ResponseWriter, r *http.Request) {
	ref := r.PathValue("ref")
	if ref == "" {
		niahttp.WriteError(w, http.StatusBadRequest, "agent ref is required")
		return
	}
	if g.monitor == nil {
		niahttp.WriteJSON(w, http.StatusOK, riskReport{AgentRef: ref, Configured: false})
		return
	}
	// Unlike observe's own fail-open read of the same call, this is a
	// direct inspection endpoint, an operator asking "what's this
	// agent's risk right now." Silently answering 0 on a read failure
	// would look identical to "this agent has never done anything
	// risky," the wrong answer for something meant to be trusted during
	// an investigation, so this fails the request instead.
	cumulative, err := g.monitor.CumulativeRisk(r.Context(), ref)
	if err != nil {
		niahttp.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	report := riskReport{
		AgentRef:   ref,
		Configured: true,
		Cumulative: cumulative,
		Thresholds: g.monitor.Thresholds(),
	}
	if g.incidents != nil {
		incidents, err := g.incidents.List(r.Context(), ref, riskReportIncidentLimit)
		if err != nil {
			niahttp.WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
		report.Incidents = incidents
	}
	niahttp.WriteJSON(w, http.StatusOK, report)
}

func (g *gateway) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		niahttp.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("POST /tools/{tool}/call", g.handleToolCall)
	// These three are operator-facing reads, not hot path. Every one of
	// them returns per-agent security state, an agent's cumulative risk
	// total, the thresholds it is being judged against, and the full
	// signal breakdown of every containment decision made about it. Before
	// this they were served to anyone who could reach this port, with no
	// authentication of any kind, while the tool-call path right above
	// them demanded a verified credential. That asymmetry was the bug.
	mux.Handle("GET /incidents", g.operatorOnly(http.HandlerFunc(g.handleListIncidents)))
	mux.Handle("GET /incidents/{id}", g.operatorOnly(http.HandlerFunc(g.handleGetIncident)))
	mux.Handle("GET /risk/{ref}", g.operatorOnly(http.HandlerFunc(g.handleRisk)))
	// The MCP endpoint, when a downstream MCP server is configured. It
	// authenticates the agent itself, in front of the protocol, see
	// mcp.go, so it is not wrapped in operatorOnly: an agent presents
	// its own credential here, never an operator token.
	if g.mcpDownstream != nil {
		mux.Handle(mcpPath, g.mcpHandler())
	}

	mux.Handle("GET /metrics", g.metricsReg)

	// Same order as cmd/api: rate limit, then body cap, then the mux.
	// The per-agent limiter is not here, it needs a resolved identity
	// and so lives inside handleToolCall.
	var h http.Handler = niahttp.MaxBytes(mux, niahttp.DefaultMaxRequestBytes)
	h = ratelimit.Middleware(g.clientLimiter, g.trustForwarded, func(string) {
		g.metrics.rateLimited.Inc("client")
	}, h, "/healthz")
	return h
}

// operatorOnly wraps an operator-facing handler in operator-token
// authentication. A nil opStore means NIA_ALLOW_UNAUTHENTICATED=1 was
// set deliberately (opauth.FromEnvEnforced refuses to produce one any
// other way, and main logs it loudly), so this is the one path where
// the handler is served unwrapped, the same explicit opt-out
// NIA_GATEWAY_INSECURE_HEADER_AUTH gives the tool-call path.
//
// Tests in this package construct gateway structs directly and leave
// opStore nil, which is why this degrades rather than panicking: the
// deployment-posture decision belongs in main, not in every handler.
func (g *gateway) operatorOnly(h http.Handler) http.Handler {
	if g.opStore == nil {
		return h
	}
	// All three are reads, so PermRead is the requirement: an on-call
	// engineer with the viewer role can investigate an agent's risk and
	// the incidents behind a containment decision, which is exactly the
	// access that role exists for, and nothing here changes state.
	return opauth.Middleware(g.opStore, opauth.Require(opauth.PermRead, h))
}

func main() {
	addr := os.Getenv("NIA_GATEWAY_ADDR")
	if addr == "" {
		addr = ":8081"
	}

	// Same policy.FromEnv switch cmd/api uses: NIA_TESSERA_BASE_URL unset
	// means the in-memory client and no Tessera dependency to run this
	// locally, set it (and the signing key alongside it) to check
	// against a real Tessera instance instead. The gateway is still not
	// where a production deployment should point its hot-path checks,
	// see TesseraHTTPClient's doc comment on why Check here reads
	// Tessera's declared state rather than live OpenFGA truth, a real
	// gateway calls OpenFGA directly the way docs/ARCHITECTURE.md
	// describes. This wiring is what makes that swap possible without
	// touching anything else in this file.
	pol, err := policy.FromEnv()
	if err != nil {
		log.Fatalf("nia-gateway: %v", err)
	}

	// Same audit.FromEnv switch cmd/api uses: NIA_AUDIT_DATABASE_URL
	// unset means an in-memory sink private to this process, set it (to
	// the same value cmd/api is started with) and both processes share
	// one real audit trail instead of two separate in-memory ones, see
	// internal/audit/from_env.go and PostgresSink's doc comment.
	auditLog, err := audit.FromEnv(context.Background())
	if err != nil {
		log.Fatalf("nia-gateway: %v", err)
	}

	// tools.FromEnvReader: NIA_TOOLS_API_URL unset means a nil Reader,
	// catalog enforcement stays off, see this file's own package doc
	// comment above for why that's the safe default rather than every
	// tool being treated as unregistered.
	toolCat, err := tools.FromEnvReader()
	if err != nil {
		log.Fatalf("nia-gateway: %v", err)
	}

	// resourcePolicyFromEnv: NIA_GATEWAY_RESOURCE_RULES_PATH unset means
	// argument inspection stays off, same additive posture as the
	// catalog check above. sensitivity.FromEnvClassifier:
	// NIA_SENSITIVITY_RULES_PATH unset means every resource classifies
	// as Public, so even with argument inspection on, nothing gets
	// blocked on a data grant until an operator actually declares a
	// resource sensitive.
	resourcePolicy, err := resourcePolicyFromEnv()
	if err != nil {
		log.Fatalf("nia-gateway: %v", err)
	}
	sensitive, err := sensitivity.FromEnvClassifier()
	if err != nil {
		log.Fatalf("nia-gateway: %v", err)
	}

	// credentials.FromEnv: unset NIA_CREDENTIALS_DATABASE_URL means an
	// in-memory store private to this process, same posture as audit
	// and policy above. This is what authn.go's credentialResolver
	// verifies bearer credentials against, and what a crossed revoke or
	// kill threshold below now actually revokes, see this variable's
	// use a few lines down: before this pass cmd/gateway had no
	// credentials.Store at all, so ActionRevoke was always an audited
	// no-op, see docs/ARCHITECTURE.md's "State convergence" section for
	// why that mattered. Set it to the same value cmd/api is started
	// with and both processes verify against, revoke against, and kill
	// against the same real store.
	creds, err := credentials.FromEnv(context.Background())
	if err != nil {
		log.Fatalf("nia-gateway: %v", err)
	}

	// monitoring.ThresholdsFromEnv: none of NIA_RISK_FLAG_AT,
	// NIA_RISK_REVOKE_AT, or NIA_RISK_KILL_AT set means monitoring is
	// skipped entirely, scorer, monitor, and incidents all stay nil, see
	// this file's own package doc comment above for why a zero-value
	// Threshold is never used as the "off" state. incidents is always
	// the in-memory reference implementation today, same process-local,
	// not-shared-across-replicas limitation as everything else in this
	// scaffold that keeps state in a map, see internal/incident's own
	// doc comment for why there's no Postgres-backed option yet, unlike
	// internal/audit, internal/credentials, and, as of this pass,
	// internal/monitoring's own risk store. monitoring.RiskStoreFromEnv:
	// unset NIA_RISK_DATABASE_URL means the running cumulative risk
	// total this Monitor compares against its thresholds is private to
	// this process, same in-memory-by-default posture as everything
	// else FromEnv in this codebase; set it to the same Postgres
	// instance every gateway replica points at and a risk score
	// climbing on one replica is the same running total every other
	// replica observes on its very next Observe call, closing the
	// specific distributed-state gap this security hardening pass
	// named directly, see docs/ARCHITECTURE.md's "Distributed state"
	// section.
	var scorer risk.Scorer
	var monitor *monitoring.Monitor
	var incidents incident.Store
	var sharedIncidents bool
	thresholds, monitoringConfigured, err := monitoring.ThresholdsFromEnv()
	if err != nil {
		log.Fatalf("nia-gateway: %v", err)
	}
	// Validated here rather than inside the monitoringConfigured branch
	// below, because a malformed rate configuration should be an error
	// whether or not anything is going to use it. Inside the branch, a
	// deployment that set NIA_RISK_RATE_WINDOW alone and no thresholds
	// would start cleanly and report nothing, and then quietly stay
	// wrong the day someone turned thresholds on.
	rateWindow, rateThreshold, err := risk.RateConfigFromEnv()
	if err != nil {
		log.Fatalf("nia-gateway: %v", err)
	}
	if rateThreshold > 0 && !monitoringConfigured {
		log.Printf("nia-gateway: rate detection is configured (%d calls per %s) but no risk threshold is set, so nothing is scored and it has no effect, see NIA_RISK_FLAG_AT, NIA_RISK_REVOKE_AT and NIA_RISK_KILL_AT", rateThreshold, rateWindow)
	}
	if monitoringConfigured {
		riskStore, err := monitoring.RiskStoreFromEnv(context.Background())
		if err != nil {
			log.Fatalf("nia-gateway: %v", err)
		}
		// risk.CallHistoryFromEnv: NIA_RISK_HISTORY_DATABASE_URL unset
		// means this process keeps its own behavioural baseline, so a
		// tool counts as novel once per replica and again after every
		// restart. Set it to the same database every replica points at
		// and the inputs to the risk total are shared the same way
		// RiskStoreFromEnv already shares the total itself, see
		// risk.PostgresCallHistory. The rate configuration was already
		// read and validated above, both of NIA_RISK_RATE_WINDOW and
		// NIA_RISK_RATE_THRESHOLD or neither, the call_rate signal
		// stays off until an operator picks numbers for their own
		// traffic.
		callHistory, sharedHistory, err := risk.CallHistoryFromEnv(context.Background())
		if err != nil {
			log.Fatalf("nia-gateway: %v", err)
		}
		if sharedHistory {
			log.Printf("nia-gateway: behavioural history is shared through %s, novel_tool and novel_transition are consistent across replicas", "NIA_RISK_HISTORY_DATABASE_URL")
		} else {
			log.Printf("nia-gateway: behavioural history is process-local, a restart or a second replica sees every tool as novel again")
		}
		if rateThreshold > 0 {
			log.Printf("nia-gateway: call_rate fires above %d calls per %s per agent", rateThreshold, rateWindow)
		} else {
			log.Printf("nia-gateway: rate detection is off, set NIA_RISK_RATE_WINDOW and NIA_RISK_RATE_THRESHOLD to enable the call_rate signal")
		}
		// incident.FromEnv: NIA_INCIDENT_DATABASE_URL unset means these
		// records live in a map that dies with the process, which is a
		// strange place to keep the evidence an incident review starts
		// from. Set it and a kill's risk value, signals and cumulative
		// total survive a restart and are visible from every replica.
		incidents, sharedIncidents, err = incident.FromEnv(context.Background())
		if err != nil {
			log.Fatalf("nia-gateway: %v", err)
		}
		if !sharedIncidents {
			log.Printf("nia-gateway: incident records are process-local and lost on restart, set NIA_INCIDENT_DATABASE_URL to keep them")
		}
		scorer = risk.NewHistoryScorerWithHistory(toolCat, sensitive, risk.DefaultWeights(), callHistory, rateWindow, rateThreshold)
		monitor = monitoring.NewMonitorWithRiskStore(thresholds, pol, creds, incidents, auditLog, riskStore)
	}

	// The default resolver is now credentialResolver: Authorization:
	// Bearer <id>.<secret>, checked against creds and, for the kill
	// case, against pol, see authn.go's own doc comment. headerResolver
	// (trust X-Agent-Ref outright, no proof of possession) is kept only
	// for local dev/testing and requires an explicit, loudly-named opt
	// in, NIA_GATEWAY_INSECURE_HEADER_AUTH=1, so it can never be what a
	// real deployment is quietly still running because nobody changed a
	// default. A deployment that sets this should not be reachable by
	// anything it doesn't fully trust.
	// tlsConfigFromEnv: unset means plain HTTP, the default every
	// deployment before this had. With a client CA bundle configured,
	// the listener verifies client certificates and mTLS becomes
	// available, see mtls.go.
	tlsConfig, mtlsEnabled, err := tlsConfigFromEnv()
	if err != nil {
		log.Fatalf("nia-gateway: %v", err)
	}

	// Certificate authentication first when it is configured: it is a
	// property of the connection rather than of a header, so a caller
	// that presented a bound certificate is that agent and a bearer
	// credential in the same request cannot change it. Both resolvers
	// produce the same ResolvedIdentity, so everything downstream of
	// authentication is identical for the two and there is no second
	// authorization path that could be missing a control.
	var resolver identity.Resolver = credentialResolver{creds: creds, pol: pol}
	if mtlsEnabled {
		resolver = chainResolver{resolvers: []identity.Resolver{
			mtlsResolver{creds: creds, pol: pol},
			credentialResolver{creds: creds, pol: pol},
		}}
		log.Printf("nia-gateway: mTLS is on, a client certificate verified against %s authenticates the agent its thumbprint is bound to, and bearer credentials keep working for callers that present none", envTLSClientCA)
	} else if tlsConfig != nil {
		log.Printf("nia-gateway: serving TLS without %s, so client certificates are not requested or verified and bearer credentials are the only authentication", envTLSClientCA)
	}
	if os.Getenv("NIA_GATEWAY_INSECURE_HEADER_AUTH") == "1" {
		log.Printf("nia-gateway: NIA_GATEWAY_INSECURE_HEADER_AUTH=1, trusting X-Agent-Ref with no credential check, this must never be set on anything reachable by an untrusted caller")
		resolver = headerResolver{headerName: "X-Agent-Ref"}
	}

	// forwarderFromEnv: NIA_GATEWAY_DOWNSTREAM_URL unset means a nil
	// Forwarder, handleToolCall stops at the authorization decision and
	// returns its own response, same as every gateway before this pass.
	// Set it to a real downstream tool/MCP server's address and an
	// authorized call actually reaches it, see forward.go.
	// mcpDownstreamFromEnv: NIA_GATEWAY_MCP_DOWNSTREAM_URL unset means
	// no MCP endpoint, same additive posture as everything else here.
	mcpDown := mcpDownstreamFromEnv()
	if mcpDown != nil {
		log.Printf("nia-gateway: %s is set, serving MCP over streamable HTTP at %s, proxying to the downstream MCP server on its own connection", envMCPDownstreamURL, mcpPath)
		if mcpDown.token == "" {
			log.Printf("nia-gateway: no %s is set, the downstream MCP server is called with no credential from NIA, the agent's own credential is never forwarded either way", envMCPDownstreamToken)
		}
	} else {
		log.Printf("nia-gateway: %s is not set, the MCP endpoint is not served", envMCPDownstreamURL)
	}

	forwarder := forwarderFromEnv()
	if forwarder != nil {
		log.Printf("nia-gateway: %s is set, authorized calls are forwarded to a real downstream tool", envDownstreamURL)
	} else {
		log.Printf("nia-gateway: %s is not set, this process only decides allow/deny, it does not forward calls to a real tool", envDownstreamURL)
	}

	// opauth.FromEnvEnforced: same posture cmd/api takes, and the same
	// single NIA_ALLOW_UNAUTHENTICATED escape hatch. This process needs
	// it for a narrower reason than cmd/api does, only the three
	// operator-facing read endpoints are affected, the tool-call path
	// authenticates agents with their own credentials either way, see
	// routes() and authn.go.
	opStore, openOnPurpose, err := opauth.FromEnvEnforced()
	if err != nil {
		log.Fatalf("nia-gateway: %v", err)
	}
	if openOnPurpose {
		log.Printf("nia-gateway: %s=1, GET /incidents, GET /incidents/{id} and GET /risk/{ref} are served to anyone who can reach this port, this must never be set on anything reachable by an untrusted caller", opauth.EnvAllowUnauthenticated)
	} else {
		log.Printf("nia-gateway: operator authentication is on, GET /incidents, GET /incidents/{id} and GET /risk/{ref} require Authorization: Bearer <operator token>")
	}

	rateCfg, err := ratelimit.FromEnv()
	if err != nil {
		log.Fatalf("nia-gateway: %v", err)
	}
	log.Printf("nia-gateway: rate limits, %.0f/s per client address (burst %d) and %.0f/s per authenticated agent (burst %d), 0 means disabled", rateCfg.PerClientRPS, rateCfg.PerClientBurst, rateCfg.PerAgentRPS, rateCfg.PerAgentBurst)

	metricsReg := metrics.NewRegistry()
	g := &gateway{
		resolver:       resolver,
		pol:            pol,
		toolCat:        toolCat,
		resourcePolicy: resourcePolicy,
		sensitive:      sensitive,
		scorer:         scorer,
		monitor:        monitor,
		incidents:      incidents,
		forwarder:      forwarder,
		opStore:        opStore,
		mcpDownstream:  mcpDown,
		clientLimiter:  rateCfg.PerClient(),
		agentLimiter:   rateCfg.PerAgent(),
		trustForwarded: rateCfg.TrustForwardedFor,
		auditLog:       auditLog,
		metrics:        newGatewayMetrics(metricsReg),
		metricsReg:     metricsReg,
	}

	srv := &http.Server{
		Addr:    addr,
		Handler: g.routes(),
		// Same reasoning as cmd/api's, with one difference that matters:
		// WriteTimeout has to exceed the downstream forwarder's own
		// 30 second client timeout (see forward.go), or this server
		// would cut off a response the gateway is still legitimately
		// waiting on and turn a slow downstream into a broken one.
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}

	if tlsConfig != nil {
		srv.TLSConfig = tlsConfig
		log.Printf("nia-gateway listening on %s over TLS", addr)
		// Paths are empty because the certificate and key are already
		// loaded into TLSConfig, which is also what makes the client CA
		// and ClientAuth settings above take effect.
		if err := srv.ListenAndServeTLS("", ""); err != nil {
			log.Fatalf("nia-gateway: %v", err)
		}
		return
	}

	log.Printf("nia-gateway listening on %s", addr)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("nia-gateway: %v", err)
	}
}
