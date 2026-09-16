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
// before mcpHandler forwards it to the underlying tool.
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
	"time"

	"github.com/bogdanticu88/nia/internal/audit"
	"github.com/bogdanticu88/nia/internal/identity"
	"github.com/bogdanticu88/nia/internal/monitoring"
	"github.com/bogdanticu88/nia/internal/policy"
	"github.com/bogdanticu88/nia/internal/registry/tools"
	"github.com/bogdanticu88/nia/internal/risk"
	"github.com/bogdanticu88/nia/internal/sensitivity"
	niahttp "github.com/bogdanticu88/nia/internal/transport/http"
)

// headerResolver is the reference identity.Resolver: it trusts a single
// header carrying the agent ref outright. Not production-grade, real
// deployments resolve identity from a verified JWT claim, an mTLS
// certificate thumbprint, or an API key lookup, the same normalization
// problem Tessera's own IIdentityResolver solves. Swapping this out is
// the first thing a real deployment should do.
type headerResolver struct {
	headerName string
}

func (h headerResolver) Resolve(ctx identity.ResolveContext) (*identity.ResolvedIdentity, error) {
	ref, ok := ctx.Headers[h.headerName]
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
	auditLog       audit.Sink
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
	headers := map[string]string{}
	for k := range r.Header {
		headers[k] = r.Header.Get(k)
	}

	resolved, err := g.resolver.Resolve(identity.ResolveContext{Headers: headers})
	if err != nil {
		niahttp.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if resolved == nil {
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

	if g.toolCat != nil {
		if _, err := g.toolCat.Get(ctx, tool); err != nil {
			if errors.Is(err, tools.ErrNotFound) {
				g.audit(ctx, "gateway.unknown_tool", resolved.Ref, fmt.Sprintf("tool=%s", tool))
				niahttp.WriteError(w, http.StatusNotFound, "tool is not registered")
				return
			}
			// Same posture as a failed policy check below: couldn't
			// determine whether this tool is even real, so this is not
			// a denial, it's "we couldn't ask," worth its own action
			// for an incident review to tell apart from "we said no."
			g.audit(ctx, "gateway.tool_lookup_error", resolved.Ref, fmt.Sprintf("tool=%s err=%v", tool, err))
			niahttp.WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}

	grant := policy.GrantForTool(tool)
	allowed, err := g.pol.Check(ctx, resolved.Ref, grant)
	if err != nil {
		// A failed check is not a denial, the policy engine couldn't be
		// reached or errored, worth its own action so an incident
		// review can tell "we said no" apart from "we couldn't ask."
		g.audit(ctx, "gateway.check_error", resolved.Ref, fmt.Sprintf("tool=%s err=%v", tool, err))
		niahttp.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !allowed {
		g.audit(ctx, "gateway.denied", resolved.Ref, fmt.Sprintf("tool=%s", tool))
		niahttp.WriteError(w, http.StatusForbidden, "agent is not authorized for this tool")
		return
	}

	// Being allowed to call the tool is not being allowed to touch
	// every resource the arguments name. This only runs when
	// resourcePolicy is configured, additive, nothing that worked
	// before this existed stops working, and even then it only demands
	// an explicit data grant for a resource classified at
	// sensitivity.Sensitive or above, see resources.go and
	// internal/sensitivity's package doc for why: an agent authorized
	// for database.query doesn't need a data grant declared for every
	// column it might ever touch, only the ones an operator has flagged
	// as actually sensitive.
	var resources []string
	if g.resourcePolicy != nil {
		resources = g.resourcePolicy.Resources(tool, body.Arguments)
		for _, resource := range resources {
			level := sensitivity.Public
			if g.sensitive != nil {
				level = g.sensitive.Classify(resource)
			}
			if level < sensitivity.Sensitive {
				continue
			}
			dataAllowed, err := g.pol.Check(ctx, resolved.Ref, policy.GrantForData(resource))
			if err != nil {
				g.audit(ctx, "gateway.check_error", resolved.Ref, fmt.Sprintf("tool=%s resource=%s err=%v", tool, resource, err))
				niahttp.WriteError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if !dataAllowed {
				g.audit(ctx, "gateway.denied", resolved.Ref, fmt.Sprintf("tool=%s resource=%s level=%s", tool, resource, level))
				niahttp.WriteError(w, http.StatusForbidden, fmt.Sprintf("agent is not authorized for resource %q", resource))
				return
			}
		}
	}

	g.audit(ctx, "gateway.allowed", resolved.Ref, fmt.Sprintf("tool=%s", tool))

	if g.monitor != nil {
		g.observe(ctx, resolved.Ref, tool, resources)
	}

	// A real deployment forwards the request to the tool's actual
	// transport (MCP, HTTP, gRPC) here. Left as the integration point
	// rather than stubbed with a fake tool response.
	niahttp.WriteJSON(w, http.StatusOK, map[string]string{
		"agent":  resolved.Ref,
		"tool":   tool,
		"status": "allowed",
	})
}

// observe scores an already-allowed call and lets internal/monitoring
// act on it. Errors here are audited and logged, not turned into a
// failed response: the call was legitimately authorized before this
// ever ran, a monitoring-side failure (the kill or revoke call itself
// erroring) is a separate incident from whether this request should
// have gone through.
func (g *gateway) observe(ctx context.Context, agentRef, tool string, resources []string) {
	score, err := g.scorer.Score(ctx, risk.CallContext{AgentRef: agentRef, Tool: tool, At: time.Now(), Resources: resources})
	if err != nil {
		g.audit(ctx, "gateway.scoring_error", agentRef, fmt.Sprintf("tool=%s err=%v", tool, err))
		log.Printf("nia-gateway: scoring failed for %s on %s: %v", agentRef, tool, err)
		return
	}

	incident := fmt.Sprintf("auto-risk-%d", time.Now().UnixNano())
	if _, err := g.monitor.Observe(ctx, score, incident); err != nil {
		g.audit(ctx, "gateway.monitoring_error", agentRef, fmt.Sprintf("tool=%s incident=%s err=%v", tool, incident, err))
		log.Printf("nia-gateway: monitoring action failed for %s on %s: %v", agentRef, tool, err)
	}
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
		log.Printf("nia-gateway: audit append failed: %v", err)
	}
}

func (g *gateway) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		niahttp.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("POST /tools/{tool}/call", g.handleToolCall)
	return mux
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

	// monitoring.ThresholdsFromEnv: none of NIA_RISK_FLAG_AT,
	// NIA_RISK_REVOKE_AT, or NIA_RISK_KILL_AT set means monitoring is
	// skipped entirely, scorer and monitor both stay nil, see this
	// file's own package doc comment above for why a zero-value
	// Threshold is never used as the "off" state. credentials.Store is
	// not wired into this process, so a configured revoke threshold
	// still works, ActionRevoke degrades to an audited no-op, see
	// monitoring.Monitor's own doc comment on NewMonitor.
	var scorer risk.Scorer
	var monitor *monitoring.Monitor
	thresholds, monitoringConfigured, err := monitoring.ThresholdsFromEnv()
	if err != nil {
		log.Fatalf("nia-gateway: %v", err)
	}
	if monitoringConfigured {
		scorer = risk.NewHistoryScorer(toolCat, sensitive, risk.DefaultWeights())
		monitor = monitoring.NewMonitor(thresholds, pol, nil, auditLog)
	}

	g := &gateway{
		resolver:       headerResolver{headerName: "X-Agent-Ref"},
		pol:            pol,
		toolCat:        toolCat,
		resourcePolicy: resourcePolicy,
		sensitive:      sensitive,
		scorer:         scorer,
		monitor:        monitor,
		auditLog:       auditLog,
	}

	srv := &http.Server{
		Addr:              addr,
		Handler:           g.routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("nia-gateway listening on %s", addr)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("nia-gateway: %v", err)
	}
}
