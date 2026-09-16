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
// Every decision this makes, allow, deny, or a check that errored
// outright, also goes to internal/audit, that's the second half of what
// audit's package doc means by "aggregates events from the gateway."
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/bogdanticu88/nia/internal/audit"
	"github.com/bogdanticu88/nia/internal/identity"
	"github.com/bogdanticu88/nia/internal/policy"
	"github.com/bogdanticu88/nia/internal/registry/tools"
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
	resolver identity.Resolver
	pol      policy.Client
	toolCat  tools.Reader // nil means catalog enforcement is not configured, see FromEnvReader
	auditLog audit.Sink
}

// handleToolCall is the shape every tool/MCP call goes through:
// resolve -> check -> forward. It's intentionally the only enforcement
// point; there is no second place in the codebase that decides whether
// a call is allowed.
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
	g.audit(ctx, "gateway.allowed", resolved.Ref, fmt.Sprintf("tool=%s", tool))

	// A real deployment forwards the request to the tool's actual
	// transport (MCP, HTTP, gRPC) here, and hands the response through
	// internal/monitoring for scoring before returning it. Left as the
	// integration point rather than stubbed with a fake tool response.
	niahttp.WriteJSON(w, http.StatusOK, map[string]string{
		"agent":  resolved.Ref,
		"tool":   tool,
		"status": "allowed",
	})
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

	g := &gateway{
		resolver: headerResolver{headerName: "X-Agent-Ref"},
		pol:      pol,
		toolCat:  toolCat,
		auditLog: auditLog,
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
