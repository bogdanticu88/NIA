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
package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/bogdanticu88/nia/internal/identity"
	"github.com/bogdanticu88/nia/internal/policy"
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
	grant := policy.GrantForTool(tool)

	allowed, err := g.pol.Check(r.Context(), resolved.Ref, grant)
	if err != nil {
		niahttp.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !allowed {
		niahttp.WriteError(w, http.StatusForbidden, "agent is not authorized for this tool")
		return
	}

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

	g := &gateway{
		resolver: headerResolver{headerName: "X-Agent-Ref"},
		pol:      pol,
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
