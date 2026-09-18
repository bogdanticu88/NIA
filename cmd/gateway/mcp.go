package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/bogdanticu88/nia/internal/identity"
	niahttp "github.com/bogdanticu88/nia/internal/transport/http"
)

// This file makes cmd/gateway an MCP proxy that understands what it is
// forwarding, rather than a pipe that moves opaque JSON.
//
// The shape, and the reason for each step being where it is:
//
//	agent -> authenticate NHI -> terminate MCP -> inspect the operation
//	      -> authorize -> risk -> enforce -> audit
//	      -> NEW downstream MCP connection -> downstream server
//
// Terminating matters. A gateway that tunnels the agent's bytes through
// can authenticate the connection and nothing else: it cannot tell
// tools/call from tools/list, cannot see which tool or which arguments,
// and so cannot make any decision that depends on what is actually being
// asked for. Everything NIA exists to do needs the operation, which
// means parsing it, which means being an MCP endpoint in its own right.
//
// The downstream connection is separate and separately authenticated.
// The agent's credential authenticates the agent to NIA and stops there;
// it is never replayed onward, because a downstream that accepts it
// could then act as that agent against anything else that trusts the
// same credential, and because NIA's whole value is being the thing that
// decides, not a conduit that passes authority along.
//
// Session model is stateless streamable HTTP. Each POST is its own
// server session, so nothing is pinned to a replica and the gateway is
// safe behind a load balancer without sticky routing. The cost is that
// each tools/call opens its own downstream session, which is an extra
// round trip per call, and the limitation is that MCP features that
// genuinely need session state (server-initiated messages over the
// standalone SSE stream, resumability, long-lived subscriptions) are not
// available. That is documented rather than worked around with
// process-local session affinity, which would quietly make the gateway
// unsafe to scale.

const (
	// envMCPDownstreamURL points at the downstream MCP server. Unset
	// means the MCP endpoint is not served at all, the same additive
	// posture every other feature in this binary takes.
	envMCPDownstreamURL = "NIA_GATEWAY_MCP_DOWNSTREAM_URL"

	// envMCPDownstreamToken is the credential NIA presents to the
	// downstream, deliberately its own and deliberately not the agent's.
	// Optional: a downstream on a trusted network may need none.
	envMCPDownstreamToken = "NIA_GATEWAY_MCP_DOWNSTREAM_TOKEN"

	// envMCPDownstreamHeader allows a downstream that wants its
	// credential somewhere other than Authorization to say so, rather
	// than forcing a deployment to put a non-bearer secret in a bearer
	// header.
	envMCPDownstreamHeader = "NIA_GATEWAY_MCP_DOWNSTREAM_HEADER"

	mcpPath           = "/mcp"
	downstreamTimeout = 30 * time.Second
)

// mcpDownstream is how this gateway reaches the downstream MCP server.
type mcpDownstream struct {
	url    string
	header string
	token  string
	client *http.Client
}

// mcpDownstreamFromEnv builds the downstream configuration. A nil result
// means no MCP downstream is configured and the /mcp endpoint is not
// registered.
func mcpDownstreamFromEnv() *mcpDownstream {
	url := strings.TrimSpace(os.Getenv(envMCPDownstreamURL))
	if url == "" {
		return nil
	}
	header := strings.TrimSpace(os.Getenv(envMCPDownstreamHeader))
	if header == "" {
		header = "Authorization"
	}
	return &mcpDownstream{
		url:    url,
		header: header,
		token:  strings.TrimSpace(os.Getenv(envMCPDownstreamToken)),
		client: &http.Client{Timeout: downstreamTimeout},
	}
}

// httpClient returns a client that attaches the downstream credential,
// if one is configured. The agent's own credential never reaches this.
func (d *mcpDownstream) httpClient() *http.Client {
	if d.token == "" {
		return d.client
	}
	return &http.Client{
		Timeout:   d.client.Timeout,
		Transport: downstreamAuthTransport{header: d.header, token: d.token, base: http.DefaultTransport},
	}
}

type downstreamAuthTransport struct {
	header string
	token  string
	base   http.RoundTripper
}

func (t downstreamAuthTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	// Cloned rather than mutated: the caller's request may be retried by
	// the transport underneath, and adding a header to a shared request
	// is how a credential ends up somewhere nobody expected.
	clone := r.Clone(r.Context())
	value := t.token
	if strings.EqualFold(t.header, "Authorization") && !strings.Contains(value, " ") {
		value = "Bearer " + value
	}
	clone.Header.Set(t.header, value)
	return t.base.RoundTrip(clone)
}

// connect opens a fresh MCP session to the downstream server. One per
// request, by design: the session model is stateless, so there is no
// pooled session to reuse and nothing to pin to this replica.
func (d *mcpDownstream) connect(ctx context.Context) (*mcp.ClientSession, error) {
	client := mcp.NewClient(&mcp.Implementation{Name: "nia-gateway", Version: "1"}, nil)
	transport := &mcp.StreamableClientTransport{
		Endpoint:   d.url,
		HTTPClient: d.httpClient(),
		// No standalone SSE stream: this session exists for the duration
		// of one proxied operation, so there is no window for a
		// server-initiated message to arrive and nowhere to deliver it.
		DisableStandaloneSSE: true,
	}
	return client.Connect(ctx, transport, nil)
}

// mcpIdentityKey carries the authenticated agent from the HTTP layer,
// where the credential lives, into the MCP layer, where the operation
// does. Unexported type so nothing outside this package can put a forged
// identity into a context.
type mcpIdentityKey struct{}

func mcpIdentityFrom(ctx context.Context) (*identity.ResolvedIdentity, bool) {
	v, ok := ctx.Value(mcpIdentityKey{}).(*identity.ResolvedIdentity)
	return v, ok
}

// mcpHandler is the HTTP handler mounted at /mcp.
//
// Authentication happens here, in front of the MCP machinery, not inside
// it. An unauthenticated caller is refused before a single byte of MCP
// is parsed, which keeps the protocol surface out of reach of anyone who
// has not proved who they are, and means an MCP parser bug cannot be
// reached without a valid credential.
func (g *gateway) mcpHandler() http.Handler {
	streamable := mcp.NewStreamableHTTPHandler(
		func(r *http.Request) *mcp.Server { return g.mcpServer(r) },
		&mcp.StreamableHTTPOptions{Stateless: true},
	)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

		// One audit line per authenticated MCP request, written here
		// rather than in the protocol middleware because the SDK
		// negotiates initialize internally and never surfaces it to a
		// receiving middleware, see mcpSecurityMiddleware. Without this,
		// an agent opening a session would leave no trace at all until
		// it called something, and "when did this agent connect" is a
		// question an incident review actually asks. It does mean a
		// tools/call produces this line as well as its own decision
		// line, which is the correlation being paid for.
		ctx := r.Context()
		g.audit(ctx, "gateway.mcp_request", resolved.Ref, fmt.Sprintf("credential=%s", resolved.CredentialID))

		// Per-client rate limiting already happened in the mux
		// middleware; the per-agent limit is inside decideToolCall,
		// where the agent is known and where it applies to the
		// operation rather than to the HTTP request, since one MCP
		// request carries exactly one operation in this transport.
		ctx = context.WithValue(ctx, mcpIdentityKey{}, resolved)
		streamable.ServeHTTP(w, r.WithContext(ctx))
	})
}

// mcpServer builds the per-request MCP server. Stateless mode gives each
// request its own session, so this is called per request and the server
// it returns is not shared.
//
// HasTools advertises the tools capability without registering any tool
// statically, which is what a proxy needs: the tools are whatever the
// downstream has, discovered at call time, not a fixed list compiled in
// here.
func (g *gateway) mcpServer(*http.Request) *mcp.Server {
	server := mcp.NewServer(
		&mcp.Implementation{Name: "nia-gateway", Version: "1", Title: "NIA security gateway"},
		&mcp.ServerOptions{
			HasTools:     true,
			Instructions: "Calls through this endpoint are authorized, risk scored and audited by NIA before they reach the downstream MCP server.",
		},
	)
	server.AddReceivingMiddleware(g.mcpSecurityMiddleware)
	return server
}

// mcpSecurityMiddleware is where the gateway stops being a proxy and
// starts being a control plane. Every inbound MCP method passes through
// here with the authenticated agent already established.
func (g *gateway) mcpSecurityMiddleware(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		resolved, ok := mcpIdentityFrom(ctx)
		if !ok {
			// Unreachable through mcpHandler, which refuses before it
			// gets here. Failing closed anyway: an MCP server reachable
			// by any other route must not be reachable without an
			// identity, and this is cheaper than trusting that nobody
			// ever mounts it differently.
			return nil, fmt.Errorf("no authenticated agent identity on this request")
		}

		switch method {
		case "tools/call":
			return g.mcpToolsCall(ctx, resolved, req)
		case "tools/list":
			return g.mcpToolsList(ctx, resolved, req)
		case "initialize":
			// Version and capability negotiation are the SDK's, and
			// correctly so: they are protocol mechanics, not security
			// decisions.
			//
			// Worth knowing rather than assuming: with this SDK the
			// initialize handshake is handled inside the server before
			// receiving middleware runs, so this case does not currently
			// fire. It is kept because the security-relevant fact, that
			// an authenticated agent opened a session, is audited at the
			// transport layer in mcpHandler instead, and because a
			// future SDK version routing initialize through middleware
			// should audit here rather than silently do nothing.
			g.audit(ctx, "gateway.mcp_initialize", resolved.Ref, fmt.Sprintf("credential=%s", resolved.CredentialID))
			return next(ctx, method, req)
		default:
			// Notifications and everything else the SDK handles. Audited
			// at a lower level of detail because they carry no side
			// effect on the downstream: this endpoint only ever forwards
			// tools/list and tools/call, so an unrecognised method
			// cannot become a downstream action by passing through here.
			g.audit(ctx, "gateway.mcp_method", resolved.Ref, fmt.Sprintf("method=%s credential=%s", method, resolved.CredentialID))
			return next(ctx, method, req)
		}
	}
}

// mcpToolsList proxies the downstream's tool list.
//
// Not authorized per tool on purpose, and worth being explicit about:
// this reports what the downstream offers, not what this agent may call.
// An agent can therefore see the name of a tool it would be refused. The
// alternative, filtering the list to the agent's grants, is a real
// option and a defensible one, but it is a behaviour change to what an
// agent sees rather than a control over what it can do, so it is not
// something to slip in silently here.
func (g *gateway) mcpToolsList(ctx context.Context, resolved *identity.ResolvedIdentity, req mcp.Request) (mcp.Result, error) {
	if g.mcpDownstream == nil {
		return nil, fmt.Errorf("no downstream MCP server is configured")
	}

	session, err := g.mcpDownstream.connect(ctx)
	if err != nil {
		g.metrics.requests.Inc("downstream_unreachable")
		g.audit(ctx, "gateway.mcp_downstream_unreachable", resolved.Ref, fmt.Sprintf("method=tools/list err=%v", err))
		return nil, fmt.Errorf("downstream MCP server is unreachable: %w", err)
	}
	defer session.Close()

	var params *mcp.ListToolsParams
	if r, ok := req.(*mcp.ListToolsRequest); ok {
		params = r.Params
	}
	result, err := session.ListTools(ctx, params)
	if err != nil {
		g.audit(ctx, "gateway.mcp_downstream_error", resolved.Ref, fmt.Sprintf("method=tools/list err=%v", err))
		return nil, err
	}

	names := make([]string, 0, len(result.Tools))
	for _, t := range result.Tools {
		names = append(names, t.Name)
	}
	g.audit(ctx, "gateway.mcp_tools_list", resolved.Ref, fmt.Sprintf("credential=%s tools=%s", resolved.CredentialID, formatFieldList(names)))
	return result, nil
}

// mcpToolsCall is the operation with a side effect, and the one the
// whole file exists for.
//
// The order is the guarantee: the security decision completes before the
// downstream connection is opened, so a refused call never reaches the
// downstream server at all. Not "reaches it and is ignored", not
// "reaches it and is undone", never sent.
func (g *gateway) mcpToolsCall(ctx context.Context, resolved *identity.ResolvedIdentity, req mcp.Request) (mcp.Result, error) {
	r, ok := req.(*mcp.CallToolRequest)
	if !ok || r.Params == nil {
		// A tools/call the SDK could not bind to its own params type.
		// Refused rather than passed along: an operation this gateway
		// cannot read is an operation it cannot authorize, and the one
		// thing it must never do is forward what it does not understand.
		g.audit(ctx, "gateway.mcp_malformed", resolved.Ref, "method=tools/call reason=unreadable_params")
		return nil, fmt.Errorf("malformed tools/call request")
	}

	tool := r.Params.Name
	if strings.TrimSpace(tool) == "" {
		g.audit(ctx, "gateway.mcp_malformed", resolved.Ref, "method=tools/call reason=empty_tool_name")
		return nil, fmt.Errorf("tools/call requires a tool name")
	}

	arguments, err := mcpArguments(r.Params.Arguments)
	if err != nil {
		// Arguments that cannot be read are arguments that cannot be
		// inspected for the resources they name, which would mean
		// authorizing the tool while being blind to what it is being
		// pointed at. Refuse.
		g.audit(ctx, "gateway.mcp_malformed", resolved.Ref, fmt.Sprintf("method=tools/call tool=%s reason=unreadable_arguments err=%v", tool, err))
		return nil, fmt.Errorf("tools/call arguments could not be read: %w", err)
	}

	decision := g.decideToolCall(ctx, resolved, tool, arguments)
	if !decision.Allowed {
		g.audit(ctx, "gateway.mcp_denied", resolved.Ref, fmt.Sprintf("tool=%s outcome=%s credential=%s", tool, decision.Outcome, resolved.CredentialID))
		return nil, fmt.Errorf("%s", decision.Message)
	}

	if g.mcpDownstream == nil {
		return nil, fmt.Errorf("no downstream MCP server is configured")
	}

	session, err := g.mcpDownstream.connect(ctx)
	if err != nil {
		g.metrics.requests.Inc("downstream_unreachable")
		g.audit(ctx, "gateway.mcp_downstream_unreachable", resolved.Ref, fmt.Sprintf("tool=%s err=%v", tool, err))
		return nil, fmt.Errorf("downstream MCP server is unreachable: %w", err)
	}
	defer session.Close()

	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: r.Params.Arguments})
	if err != nil {
		// A downstream protocol error, distinct from a tool that ran and
		// reported failure, which comes back as a result with IsError.
		g.metrics.requests.Inc("downstream_server_error")
		g.audit(ctx, "gateway.mcp_downstream_error", resolved.Ref, fmt.Sprintf("tool=%s credential=%s err=%v", tool, resolved.CredentialID, err))
		return nil, err
	}

	g.inspectMCPResult(ctx, resolved, tool, result)
	return result, nil
}

// inspectMCPResult puts the downstream's response through the same
// security-aware boundary a REST forward goes through: audited,
// correlated to the agent and tool, and checked for sensitive fields the
// agent holds no grant for, which feeds the risk total exactly as the
// REST path does, see inspectResponseFields.
//
// The response is inspected rather than streamed past, which is the
// requirement this satisfies. It is not a DLP engine and does not try to
// be, see response.go for what that check is and is not.
func (g *gateway) inspectMCPResult(ctx context.Context, resolved *identity.ResolvedIdentity, tool string, result *mcp.CallToolResult) {
	if result == nil {
		return
	}

	body, err := json.Marshal(result)
	if err != nil {
		g.audit(ctx, "gateway.mcp_response_unreadable", resolved.Ref, fmt.Sprintf("tool=%s err=%v", tool, err))
		return
	}

	detail := fmt.Sprintf("tool=%s credential=%s bytes=%d is_error=%t", tool, resolved.CredentialID, len(body), result.IsError)
	if result.IsError {
		g.metrics.requests.Inc("downstream_client_error")
		g.audit(ctx, "gateway.mcp_tool_error", resolved.Ref, detail)
	} else {
		g.metrics.requests.Inc("downstream_ok")
		g.audit(ctx, "gateway.mcp_tool_ok", resolved.Ref, detail)
	}

	g.inspectResponseFields(ctx, resolved.Ref, tool, resolved.CredentialID, detail, body)
}

// mcpArguments normalizes MCP's untyped arguments into the map the
// resource policy reads. MCP allows any JSON value; a non-object is not
// an error, it simply names no resources.
func mcpArguments(raw any) (map[string]any, error) {
	if raw == nil {
		return nil, nil
	}
	if m, ok := raw.(map[string]any); ok {
		return m, nil
	}
	// json.RawMessage and friends: round trip rather than guess at the
	// concrete type the SDK happened to decode into.
	encoded, err := json.Marshal(raw)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(encoded, &m); err != nil {
		// Valid MCP, just not an object. Nothing to inspect.
		return nil, nil
	}
	return m, nil
}
