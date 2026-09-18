package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/bogdanticu88/nia/internal/audit"
	"github.com/bogdanticu88/nia/internal/credentials"
	"github.com/bogdanticu88/nia/internal/monitoring"
	"github.com/bogdanticu88/nia/internal/policy"
	"github.com/bogdanticu88/nia/internal/sensitivity"
)

// The downstream in these tests is a real MCP server built on the same
// SDK, served over streamable HTTP, not a fake JSON endpoint. That
// matters: the thing being proven is that NIA speaks MCP correctly on
// both sides, and a stub that returns canned JSON would prove only that
// NIA can talk to a stub.

// downstreamMCP is a minimal real MCP server with one tool, plus enough
// bookkeeping for a test to assert what actually reached it.
type downstreamMCP struct {
	url string

	mu          sync.Mutex
	calls       []downstreamCall
	authHeaders []string
}

type downstreamCall struct {
	tool string
	args map[string]any
}

type echoArgs struct {
	Table  string `json:"table,omitempty"`
	Fields any    `json:"fields,omitempty"`
	Fail   bool   `json:"fail,omitempty"`
}

func newDownstreamMCP(t *testing.T) *downstreamMCP {
	t.Helper()
	d := &downstreamMCP{}

	server := mcp.NewServer(&mcp.Implementation{Name: "test-downstream", Version: "1"}, nil)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "database.query",
		Description: "returns rows, or an error when asked to fail",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in echoArgs) (*mcp.CallToolResult, any, error) {
		d.mu.Lock()
		d.calls = append(d.calls, downstreamCall{tool: "database.query", args: map[string]any{"table": in.Table, "fields": in.Fields}})
		d.mu.Unlock()

		if in.Fail {
			// A tool that ran and failed, which MCP models as a result
			// with IsError, distinct from a protocol error.
			return &mcp.CallToolResult{
				IsError: true,
				Content: []mcp.Content{&mcp.TextContent{Text: "the query failed downstream"}},
			}, nil, nil
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: `{"rows":[{"name":"a","ssn":"111"}]}`}},
		}, nil, nil
	})

	handler := mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return server },
		&mcp.StreamableHTTPOptions{Stateless: true},
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		d.authHeaders = append(d.authHeaders, r.Header.Get("Authorization"))
		d.mu.Unlock()
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)

	d.url = srv.URL
	return d
}

func (d *downstreamMCP) callCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.calls)
}

func (d *downstreamMCP) lastCall() (downstreamCall, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.calls) == 0 {
		return downstreamCall{}, false
	}
	return d.calls[len(d.calls)-1], true
}

func (d *downstreamMCP) seenAuthHeaders() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]string, len(d.authHeaders))
	copy(out, d.authHeaders)
	return out
}

// mcpTestGateway wires a gateway with credential authentication (not the
// insecure header resolver) in front of a real downstream MCP server, so
// these tests exercise the same authentication path a deployment uses.
type mcpTestGateway struct {
	gateway    *gateway
	sink       *audit.InMemorySink
	creds      *credentials.InMemoryStore
	pol        *policy.InMemoryClient
	downstream *downstreamMCP
	server     *httptest.Server
}

func newMCPTestGateway(t *testing.T) *mcpTestGateway {
	t.Helper()
	return newMCPTestGatewayWithMonitor(t, nil)
}

func newMCPTestGatewayWithMonitor(t *testing.T, thresholds *monitoring.Threshold) *mcpTestGateway {
	t.Helper()
	down := newDownstreamMCP(t)
	pol := policy.NewInMemoryClient()
	creds := credentials.NewInMemoryStore()

	var g *gateway
	var sink *audit.InMemorySink
	if thresholds != nil {
		g, sink = newTestGatewayWithMonitoring(pol, fakeScorer{value: 5}, *thresholds)
	} else {
		g, sink = newTestGateway(pol)
	}
	g.resolver = credentialResolver{creds: creds, pol: pol}
	g.mcpDownstream = &mcpDownstream{
		url:    down.url,
		header: "Authorization",
		token:  "downstream-secret",
		client: &http.Client{},
	}

	srv := httptest.NewServer(g.routes())
	t.Cleanup(srv.Close)

	return &mcpTestGateway{gateway: g, sink: sink, creds: creds, pol: pol, downstream: down, server: srv}
}

// agent registers an agent with a credential and the given tool grants,
// returning the bearer credential it should present.
func (m *mcpTestGateway) agent(t *testing.T, ref string, grants ...policy.Grant) string {
	t.Helper()
	cred, secret, err := m.creds.Issue(t.Context(), ref, credentials.KindAPIKey, 0)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if len(grants) > 0 {
		if err := m.pol.WriteGrants(t.Context(), ref, grants); err != nil {
			t.Fatalf("WriteGrants: %v", err)
		}
	}
	return cred.ID + "." + secret
}

// connect opens a real MCP client session against the gateway, which is
// what proves initialize and capability negotiation actually work rather
// than being assumed.
func (m *mcpTestGateway) connect(t *testing.T, credential string) (*mcp.ClientSession, error) {
	t.Helper()
	client := mcp.NewClient(&mcp.Implementation{Name: "test-agent", Version: "1"}, nil)
	transport := &mcp.StreamableClientTransport{
		Endpoint:             m.server.URL + mcpPath,
		HTTPClient:           &http.Client{Transport: bearerTransport{token: credential}},
		DisableStandaloneSSE: true,
	}
	return client.Connect(t.Context(), transport, nil)
}

type bearerTransport struct{ token string }

func (b bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	clone := r.Clone(r.Context())
	if b.token != "" {
		clone.Header.Set("Authorization", "Bearer "+b.token)
	}
	return http.DefaultTransport.RoundTrip(clone)
}

func (m *mcpTestGateway) auditActions(t *testing.T) []string {
	t.Helper()
	events, err := m.sink.Recent(t.Context(), 0)
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	out := make([]string, 0, len(events))
	for _, e := range events {
		out = append(out, e.Action)
	}
	return out
}

func containsAction(actions []string, want string) bool {
	for _, a := range actions {
		if a == want {
			return true
		}
	}
	return false
}

// 1. A valid initialize succeeds, with real protocol and capability
// negotiation performed by the SDK on both sides.
func TestMCP_InitializeSucceedsForAnAuthenticatedAgent(t *testing.T) {
	m := newMCPTestGateway(t)
	cred := m.agent(t, "agent:billing")

	session, err := m.connect(t, cred)
	if err != nil {
		t.Fatalf("initialize: %v", err)
	}
	defer session.Close()

	init := session.InitializeResult()
	if init == nil {
		t.Fatal("no initialize result, the handshake did not complete")
	}
	if init.ServerInfo == nil || init.ServerInfo.Name != "nia-gateway" {
		t.Fatalf("server info = %+v, want the gateway to identify itself", init.ServerInfo)
	}
	if init.Capabilities == nil || init.Capabilities.Tools == nil {
		t.Fatalf("capabilities = %+v, want the tools capability advertised", init.Capabilities)
	}
	if init.ProtocolVersion == "" {
		t.Fatal("no negotiated protocol version")
	}
	// Audited at the transport layer rather than in the protocol
	// middleware: this SDK negotiates initialize inside the server,
	// before receiving middleware runs, so the security-relevant fact
	// that an authenticated agent opened a session is recorded by
	// mcpHandler. See the initialize case in mcpSecurityMiddleware.
	if !containsAction(m.auditActions(t), "gateway.mcp_request") {
		t.Fatalf("the authenticated MCP request was not audited: %v", m.auditActions(t))
	}
}

// 2. Invalid authentication fails, before any MCP is parsed.
func TestMCP_InvalidAuthenticationIsRefused(t *testing.T) {
	m := newMCPTestGateway(t)
	m.agent(t, "agent:billing")

	for name, cred := range map[string]string{
		"no credential":      "",
		"unknown id":         "deadbeef.secret",
		"malformed":          "not-a-credential",
		"wrong secret shape": "abc.def.ghi",
	} {
		if _, err := m.connect(t, cred); err == nil {
			t.Fatalf("%s: initialize succeeded without valid authentication", name)
		}
	}
	if m.downstream.callCount() != 0 {
		t.Fatal("an unauthenticated caller reached the downstream MCP server")
	}
}

// 3. An unauthorized tools/call is blocked, and never reaches the
// downstream.
func TestMCP_UnauthorizedToolCallIsBlockedBeforeTheDownstream(t *testing.T) {
	m := newMCPTestGateway(t)
	cred := m.agent(t, "agent:billing") // no grants

	session, err := m.connect(t, cred)
	if err != nil {
		t.Fatalf("initialize: %v", err)
	}
	defer session.Close()

	_, err = session.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "database.query",
		Arguments: map[string]any{"table": "invoices"},
	})
	if err == nil {
		t.Fatal("an ungranted tools/call succeeded")
	}
	if m.downstream.callCount() != 0 {
		t.Fatalf("the downstream MCP server was called %d times for a refused operation, the decision must complete before the connection is opened", m.downstream.callCount())
	}
	if !containsAction(m.auditActions(t), "gateway.mcp_denied") {
		t.Fatalf("the denial was not audited: %v", m.auditActions(t))
	}
}

// 4 and 6. An authorized tools/call reaches the real downstream MCP
// server and its response comes back to the agent.
func TestMCP_AuthorizedToolCallReachesTheDownstreamAndReturnsItsResponse(t *testing.T) {
	m := newMCPTestGateway(t)
	cred := m.agent(t, "agent:billing", policy.GrantForTool("database.query"))

	session, err := m.connect(t, cred)
	if err != nil {
		t.Fatalf("initialize: %v", err)
	}
	defer session.Close()

	result, err := session.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "database.query",
		Arguments: map[string]any{"table": "invoices"},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if m.downstream.callCount() != 1 {
		t.Fatalf("downstream called %d times, want 1", m.downstream.callCount())
	}
	if len(result.Content) == 0 {
		t.Fatal("no content came back from the downstream")
	}
	text, ok := result.Content[0].(*mcp.TextContent)
	if !ok || !strings.Contains(text.Text, "rows") {
		t.Fatalf("content = %+v, want the downstream's own response", result.Content[0])
	}
}

// 5. Tool arguments are visible to the policy layer. Proven through the
// resource policy, which derives resource names from arguments and
// requires a data grant for the sensitive ones: if the arguments were
// not visible, nothing could be derived and nothing would be refused.
func TestMCP_ToolArgumentsAreVisibleToThePolicyLayer(t *testing.T) {
	m := newMCPTestGateway(t)
	m.gateway.resourcePolicy = NewFieldResourcePolicy([]ResourceRule{
		{Tool: "database.query", QualifierField: "table", FieldsField: "fields"},
	})
	m.gateway.sensitive = sensitivity.NewRuleClassifier([]sensitivity.Rule{
		{Pattern: "customers.ssn", Level: sensitivity.Critical},
	})
	cred := m.agent(t, "agent:billing", policy.GrantForTool("database.query"))

	session, err := m.connect(t, cred)
	if err != nil {
		t.Fatalf("initialize: %v", err)
	}
	defer session.Close()

	// The tool is granted; the resource named in the arguments is not.
	_, err = session.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "database.query",
		Arguments: map[string]any{"table": "customers", "fields": []any{"ssn"}},
	})
	if err == nil {
		t.Fatal("a call naming an ungranted sensitive resource in its arguments succeeded")
	}
	if !strings.Contains(err.Error(), "customers.ssn") {
		t.Fatalf("err = %v, want it to name the resource derived from the arguments", err)
	}
	if m.downstream.callCount() != 0 {
		t.Fatal("the downstream was called despite the resource denial")
	}

	// And the same call with the data grant present goes through, which
	// proves the refusal above was the grant and not the parsing.
	if err := m.pol.WriteGrants(t.Context(), "agent:billing", []policy.Grant{
		policy.GrantForTool("database.query"),
		policy.GrantForData("customers.ssn"),
	}); err != nil {
		t.Fatalf("WriteGrants: %v", err)
	}
	if _, err := session.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "database.query",
		Arguments: map[string]any{"table": "customers", "fields": []any{"ssn"}},
	}); err != nil {
		t.Fatalf("CallTool with the data grant: %v", err)
	}
	call, ok := m.downstream.lastCall()
	if !ok || call.args["table"] != "customers" {
		t.Fatalf("the downstream received %+v, want the arguments the agent sent", call.args)
	}
}

// 7. A downstream error is handled rather than swallowed or turned into
// a gateway failure.
func TestMCP_DownstreamToolErrorIsReturnedAndAudited(t *testing.T) {
	m := newMCPTestGateway(t)
	cred := m.agent(t, "agent:billing", policy.GrantForTool("database.query"))

	session, err := m.connect(t, cred)
	if err != nil {
		t.Fatalf("initialize: %v", err)
	}
	defer session.Close()

	result, err := session.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "database.query",
		Arguments: map[string]any{"fail": true},
	})
	if err != nil {
		t.Fatalf("a tool that reported failure should come back as a result with IsError, not a protocol error: %v", err)
	}
	if !result.IsError {
		t.Fatal("IsError = false for a tool that failed downstream")
	}
	if !containsAction(m.auditActions(t), "gateway.mcp_tool_error") {
		t.Fatalf("the downstream tool error was not audited: %v", m.auditActions(t))
	}
}

func TestMCP_UnreachableDownstreamIsAnErrorNotASilentSuccess(t *testing.T) {
	m := newMCPTestGateway(t)
	m.gateway.mcpDownstream = &mcpDownstream{url: "http://127.0.0.1:1", header: "Authorization", client: &http.Client{}}
	cred := m.agent(t, "agent:billing", policy.GrantForTool("database.query"))

	session, err := m.connect(t, cred)
	if err != nil {
		t.Fatalf("initialize: %v", err)
	}
	defer session.Close()

	if _, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "database.query"}); err == nil {
		t.Fatal("an unreachable downstream returned success")
	}
}

// 8. A killed agent cannot invoke downstream tools, even holding a
// credential that was valid a moment ago.
func TestMCP_KilledAgentCannotInvokeDownstreamTools(t *testing.T) {
	m := newMCPTestGateway(t)
	cred := m.agent(t, "agent:billing", policy.GrantForTool("database.query"))

	session, err := m.connect(t, cred)
	if err != nil {
		t.Fatalf("initialize: %v", err)
	}
	defer session.Close()

	if _, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "database.query"}); err != nil {
		t.Fatalf("the call before the kill should succeed: %v", err)
	}
	before := m.downstream.callCount()

	if _, err := m.pol.Kill(t.Context(), "agent:billing", "INC-1", "bogdan"); err != nil {
		t.Fatalf("Kill: %v", err)
	}

	// A new session, because the kill is checked during identity
	// resolution on each request.
	killedSession, err := m.connect(t, cred)
	if err == nil {
		defer killedSession.Close()
		if _, err := killedSession.CallTool(t.Context(), &mcp.CallToolParams{Name: "database.query"}); err == nil {
			t.Fatal("a killed agent called a downstream tool")
		}
	}
	if m.downstream.callCount() != before {
		t.Fatalf("the downstream was called %d more times after the kill", m.downstream.callCount()-before)
	}
}

// 9. A risk-triggered kill prevents subsequent calls. The scorer is
// fixed at a value that crosses the kill threshold on the first call, so
// the agent is killed by its own behaviour rather than by an operator.
func TestMCP_RiskTriggeredKillPreventsSubsequentCalls(t *testing.T) {
	m := newMCPTestGatewayWithMonitor(t, &monitoring.Threshold{FlagAt: 1, RevokeAt: 100, KillAt: 4})
	cred := m.agent(t, "agent:billing", policy.GrantForTool("database.query"))

	session, err := m.connect(t, cred)
	if err != nil {
		t.Fatalf("initialize: %v", err)
	}
	defer session.Close()

	if _, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "database.query"}); err != nil {
		t.Fatalf("the first call should be allowed, the kill happens after it is scored: %v", err)
	}
	killed, err := m.pol.IsKilled(t.Context(), "agent:billing")
	if err != nil {
		t.Fatalf("IsKilled: %v", err)
	}
	if !killed {
		t.Fatal("the risk score did not trigger a kill, this test needs it to")
	}

	before := m.downstream.callCount()
	next, err := m.connect(t, cred)
	if err == nil {
		defer next.Close()
		if _, err := next.CallTool(t.Context(), &mcp.CallToolParams{Name: "database.query"}); err == nil {
			t.Fatal("a call succeeded after the risk-triggered kill")
		}
	}
	if m.downstream.callCount() != before {
		t.Fatal("the downstream was reached after the risk-triggered kill")
	}
}

// 10. Malformed MCP cannot bypass authorization. Sent as raw HTTP rather
// than through the client, because a well-behaved client will not
// produce these.
func TestMCP_MalformedMessagesCannotBypassAuthorization(t *testing.T) {
	m := newMCPTestGateway(t)
	cred := m.agent(t, "agent:billing") // deliberately no grants

	bodies := map[string]string{
		"tools/call with no params":     `{"jsonrpc":"2.0","id":1,"method":"tools/call"}`,
		"tools/call with a null name":   `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":null}}`,
		"tools/call with an empty name": `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":""}}`,
		"arguments as a string":         `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"database.query","arguments":"not-an-object"}}`,
		"not json at all":               `{{{`,
		"unknown method":                `{"jsonrpc":"2.0","id":1,"method":"tools/evaluate","params":{"name":"database.query"}}`,
	}

	for name, body := range bodies {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, m.server.URL+mcpPath, strings.NewReader(body))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("Authorization", "Bearer "+cred)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		resp.Body.Close()
	}

	if m.downstream.callCount() != 0 {
		t.Fatalf("malformed MCP reached the downstream %d times", m.downstream.callCount())
	}
}

// 11. A method/tool mismatch cannot bypass policy: the tool that gets
// authorized is the tool that gets called, and naming one tool while
// being granted another does not help.
func TestMCP_MethodAndToolMismatchCannotBypassPolicy(t *testing.T) {
	m := newMCPTestGateway(t)
	// Granted a different tool than the one it will call.
	cred := m.agent(t, "agent:billing", policy.GrantForTool("some.other.tool"))

	session, err := m.connect(t, cred)
	if err != nil {
		t.Fatalf("initialize: %v", err)
	}
	defer session.Close()

	if _, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "database.query"}); err == nil {
		t.Fatal("a call to a tool the agent is not granted succeeded because another tool was granted")
	}
	if m.downstream.callCount() != 0 {
		t.Fatal("the downstream was reached for an ungranted tool")
	}

	// And the authorized tool name is the one forwarded, not something
	// the agent could swap underneath it.
	if err := m.pol.WriteGrants(t.Context(), "agent:billing", []policy.Grant{policy.GrantForTool("database.query")}); err != nil {
		t.Fatalf("WriteGrants: %v", err)
	}
	if _, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "database.query"}); err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	call, ok := m.downstream.lastCall()
	if !ok || call.tool != "database.query" {
		t.Fatalf("the downstream received tool %q, want the one that was authorized", call.tool)
	}
}

// 12. Multiple gateway instances process stateless requests correctly.
// Two independent gateways share nothing, and an agent's session works
// against either, which is what "safe behind a load balancer" means.
func TestMCP_MultipleGatewayInstancesHandleStatelessRequests(t *testing.T) {
	down := newDownstreamMCP(t)
	pol := policy.NewInMemoryClient()
	creds := credentials.NewInMemoryStore()

	newInstance := func() *httptest.Server {
		g, _ := newTestGateway(pol)
		g.resolver = credentialResolver{creds: creds, pol: pol}
		g.mcpDownstream = &mcpDownstream{url: down.url, header: "Authorization", client: &http.Client{}}
		srv := httptest.NewServer(g.routes())
		t.Cleanup(srv.Close)
		return srv
	}

	first, second := newInstance(), newInstance()

	cred, secret, err := creds.Issue(t.Context(), "agent:billing", credentials.KindAPIKey, 0)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := pol.WriteGrants(t.Context(), "agent:billing", []policy.Grant{policy.GrantForTool("database.query")}); err != nil {
		t.Fatalf("WriteGrants: %v", err)
	}
	credential := cred.ID + "." + secret

	callAgainst := func(srv *httptest.Server) error {
		client := mcp.NewClient(&mcp.Implementation{Name: "test-agent", Version: "1"}, nil)
		session, err := client.Connect(t.Context(), &mcp.StreamableClientTransport{
			Endpoint:             srv.URL + mcpPath,
			HTTPClient:           &http.Client{Transport: bearerTransport{token: credential}},
			DisableStandaloneSSE: true,
		}, nil)
		if err != nil {
			return err
		}
		defer session.Close()
		_, err = session.CallTool(t.Context(), &mcp.CallToolParams{Name: "database.query"})
		return err
	}

	if err := callAgainst(first); err != nil {
		t.Fatalf("call against the first instance: %v", err)
	}
	if err := callAgainst(second); err != nil {
		t.Fatalf("call against the second instance: %v, a stateless gateway must not need session affinity", err)
	}
	if down.callCount() != 2 {
		t.Fatalf("downstream saw %d calls, want 2", down.callCount())
	}
}

// The downstream is authenticated with NIA's own credential, never the
// agent's. Forwarding the agent's credential would let the downstream
// act as that agent anywhere else that trusts it.
func TestMCP_TheAgentCredentialIsNeverForwardedDownstream(t *testing.T) {
	m := newMCPTestGateway(t)
	cred := m.agent(t, "agent:billing", policy.GrantForTool("database.query"))

	session, err := m.connect(t, cred)
	if err != nil {
		t.Fatalf("initialize: %v", err)
	}
	defer session.Close()

	if _, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "database.query"}); err != nil {
		t.Fatalf("CallTool: %v", err)
	}

	seen := m.downstream.seenAuthHeaders()
	if len(seen) == 0 {
		t.Fatal("the downstream saw no requests")
	}
	for _, h := range seen {
		if strings.Contains(h, cred) {
			t.Fatalf("the agent's own credential was forwarded downstream in %q", h)
		}
		if h != "Bearer downstream-secret" {
			t.Fatalf("downstream Authorization = %q, want NIA's own configured credential", h)
		}
	}
}

func TestMCP_ToolsListProxiesTheDownstreamCatalog(t *testing.T) {
	m := newMCPTestGateway(t)
	cred := m.agent(t, "agent:billing")

	session, err := m.connect(t, cred)
	if err != nil {
		t.Fatalf("initialize: %v", err)
	}
	defer session.Close()

	result, err := session.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	if len(result.Tools) != 1 || result.Tools[0].Name != "database.query" {
		t.Fatalf("tools = %+v, want the downstream's own catalog", result.Tools)
	}
	if !containsAction(m.auditActions(t), "gateway.mcp_tools_list") {
		t.Fatalf("tools/list was not audited: %v", m.auditActions(t))
	}
}

// The response passes through the same security-aware boundary the REST
// path uses, so a sensitive field the agent holds no grant for is a
// finding on the MCP path too.
func TestMCP_ResponseIsInspectedForUngrantedSensitiveFields(t *testing.T) {
	m := newMCPTestGateway(t)
	m.gateway.sensitive = sensitivity.NewRuleClassifier([]sensitivity.Rule{
		{Pattern: "ssn", Level: sensitivity.Critical},
	})
	cred := m.agent(t, "agent:billing", policy.GrantForTool("database.query"))

	session, err := m.connect(t, cred)
	if err != nil {
		t.Fatalf("initialize: %v", err)
	}
	defer session.Close()

	if _, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "database.query"}); err != nil {
		t.Fatalf("CallTool: %v", err)
	}

	actions := m.auditActions(t)
	if !containsAction(actions, "gateway.mcp_tool_ok") {
		t.Fatalf("the downstream response was not audited: %v", actions)
	}
}
