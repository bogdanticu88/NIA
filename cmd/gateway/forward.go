package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Forwarder sends an authorized tool call on to the real downstream
// tool or MCP server and returns what came back. This is the step that
// turns cmd/gateway into an actual enforcement proxy rather than a
// decision service that stops at "allowed": everything above it in
// handleToolCall, identity resolution, credential state, kill state,
// OpenFGA/Tessera authorization, argument-level resource checks, has
// already run and passed before Forward is ever called. Forwarding
// itself never decides whether a call happens, only what happens once
// every gate has already said yes, which is why it's a separate
// interface rather than folded into the resolver or the policy client,
// the three concerns (who, may-they, what-happens) stay independently
// swappable and independently testable the same way this codebase
// already keeps identity.Resolver and policy.Client apart.
type Forwarder interface {
	Forward(ctx context.Context, tool string, arguments map[string]any) (ForwardResult, error)
}

// ForwardResult is what the downstream server actually returned.
// StatusCode and Body are exactly what came back, this is a proxy, not
// a translator: an agent calling through the gateway sees the same
// tool response it would see calling the tool directly, plus the
// gateway's security layer in front of it. Duration is kept because a
// downstream tool suddenly taking far longer than usual is itself
// worth having in the audit record, even before anything reads it for
// risk scoring.
type ForwardResult struct {
	StatusCode int
	Body       []byte
	Duration   time.Duration
}

// maxDownstreamResponseBytes bounds how much of a downstream response
// the gateway will read into memory. An authorized call is not the
// same thing as a fully trusted downstream: an unbounded read here
// would let a misbehaving or compromised downstream tool exhaust the
// gateway's memory on every single call. A response that hits this cap
// is truncated, not rejected, and inspectAndAuditDownstream in main.go
// records that it happened rather than silently handing back a partial
// body with no signal that anything was cut off.
const maxDownstreamResponseBytes = 10 << 20 // 10 MiB

// HTTPForwarder is the real implementation. It POSTs the tool call as
// JSON to <baseURL>/<tool>, the same toolCallRequest shape a caller
// talking to the gateway itself sends, so a downstream test server can
// be as simple as another instance of this same request/response
// contract, see forward_test.go and the integration tests in
// gateway_test.go for exactly that.
//
// baseURL is one configured downstream target for the whole gateway
// (NIA_GATEWAY_DOWNSTREAM_URL), not a per-tool routing table. That's a
// stated simplification, not a hidden one: internal/registry/tools.Tool
// has no endpoint field today, adding per-tool downstream routing would
// mean extending the catalog schema and every place that constructs a
// Tool, a larger change than what closing this specific gap needs. A
// single shared downstream target is enough to prove the actual thing
// this item is about, that the gateway forwards and inspects a real
// response instead of returning a canned one, and it's what a
// deployment that puts one MCP router or one API gateway behind NIA
// looks like anyway. Splitting this per tool later is additive, not a
// redesign, whenever there's a real deployment that needs it.
type HTTPForwarder struct {
	baseURL    string
	httpClient *http.Client
}

// NewHTTPForwarder builds a forwarder against baseURL, the downstream
// tool server or MCP router's own address.
func NewHTTPForwarder(baseURL string) *HTTPForwarder {
	return &HTTPForwarder{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

func (f *HTTPForwarder) Forward(ctx context.Context, tool string, arguments map[string]any) (ForwardResult, error) {
	payload, err := json.Marshal(toolCallRequest{Arguments: arguments})
	if err != nil {
		return ForwardResult{}, fmt.Errorf("downstream: encoding request: %w", err)
	}

	reqURL := f.baseURL + "/" + strings.TrimLeft(tool, "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(payload))
	if err != nil {
		return ForwardResult{}, fmt.Errorf("downstream: building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	start := time.Now()
	resp, err := f.httpClient.Do(req)
	duration := time.Since(start)
	if err != nil {
		// The call was authorized but the downstream itself couldn't be
		// reached at all, a network failure, a timeout, a connection
		// refused. This is not the same outcome as the downstream
		// answering with an error status, the caller in main.go turns
		// this into 502, not whatever the downstream would have said.
		return ForwardResult{}, fmt.Errorf("downstream: calling %s: %w", reqURL, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDownstreamResponseBytes))
	if err != nil {
		return ForwardResult{}, fmt.Errorf("downstream: reading response from %s: %w", reqURL, err)
	}
	return ForwardResult{StatusCode: resp.StatusCode, Body: body, Duration: duration}, nil
}

var _ Forwarder = (*HTTPForwarder)(nil)

// envDownstreamURL is the one environment variable this file reads.
// Unset means forwarderFromEnv returns a nil Forwarder, the same
// additive posture every other optional gateway feature in this
// codebase follows (see cmd/gateway's own package doc comment): a
// deployment that never sets this gets the exact pre-forwarding
// behavior, handleToolCall stops at the "allowed" decision and returns
// its own response, it does not stub a fake downstream success either
// before or after this change, so there's nothing misleading in the
// unconfigured case.
const envDownstreamURL = "NIA_GATEWAY_DOWNSTREAM_URL"

func forwarderFromEnv() Forwarder {
	base := strings.TrimSpace(os.Getenv(envDownstreamURL))
	if base == "" {
		return nil
	}
	return NewHTTPForwarder(base)
}
