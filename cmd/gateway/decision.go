package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/bogdanticu88/nia/internal/identity"
	"github.com/bogdanticu88/nia/internal/policy"
	"github.com/bogdanticu88/nia/internal/registry/tools"
	"github.com/bogdanticu88/nia/internal/sensitivity"
)

// This file holds the one security decision every tool call goes
// through, whichever protocol it arrived on.
//
// It exists because there are two front doors now: the original
// POST /tools/{tool}/call, and MCP over streamable HTTP (mcp.go). Two
// front doors with two copies of the pipeline is how one of them
// quietly ends up missing a check, and "the MCP path skips the
// resource-level data grant" is precisely the bug nobody would notice
// until it mattered. So the pipeline lives here once and both
// transports call it, and the tests assert the MCP path is subject to
// every control the REST path is.
//
// What it deliberately does not do is anything protocol-specific.
// Mapping a decision onto an HTTP status or an MCP error belongs to the
// transport, because those are genuinely different vocabularies.

// decisionOutcome is both the metrics label and the reason a caller is
// being refused, kept as one value so the two can never disagree.
type decisionOutcome string

const (
	outcomeAllowed         decisionOutcome = "allowed"
	outcomeRateLimited     decisionOutcome = "rate_limited"
	outcomeUnknownTool     decisionOutcome = "unknown_tool"
	outcomeToolLookupError decisionOutcome = "tool_lookup_error"
	outcomeCheckError      decisionOutcome = "check_error"
	outcomeDeniedTool      decisionOutcome = "denied_tool"
	outcomeDeniedResource  decisionOutcome = "denied_resource"
)

// toolCallDecision is what the pipeline concluded. Allowed is the only
// field a caller strictly has to read; the rest exist so a transport
// can produce a useful answer rather than a bare refusal.
//
// Risk is set when monitoring is configured and the call was allowed. It
// carries the same numbers internal/monitoring already acted on, not a
// second opinion computed for display.
type toolCallDecision struct {
	Allowed   bool
	Outcome   decisionOutcome
	Message   string
	Err       error    // set for the two "we couldn't ask" outcomes
	Resources []string // resource names the arguments were found to touch
	Risk      *riskInfo
}

// HTTPStatus maps a decision onto the status the REST transport has
// always returned for it. Kept next to the decision rather than in the
// handler so the MCP path can reuse the same mapping where it makes
// sense and diverge deliberately where it does not.
func (d toolCallDecision) HTTPStatus() int {
	switch d.Outcome {
	case outcomeAllowed:
		return http.StatusOK
	case outcomeRateLimited:
		return http.StatusTooManyRequests
	case outcomeUnknownTool:
		return http.StatusNotFound
	case outcomeDeniedTool, outcomeDeniedResource:
		return http.StatusForbidden
	default:
		return http.StatusInternalServerError
	}
}

// decideToolCall runs identity-bound authorization, argument inspection,
// and risk evaluation for one tool call, in that order, and audits every
// branch. The caller has already resolved the identity; everything after
// that is here.
//
// Ordering is the security property, not an implementation detail. The
// rate limit comes first so a flood costs as little as possible. The
// catalog and grant checks come before argument inspection so an agent
// with no business calling a tool never reaches the code that parses its
// arguments. Risk runs last, on a call that is already authorized,
// because it is allowed to end with the agent being killed and that has
// to be a decision about a legitimate call rather than a rejected one.
func (g *gateway) decideToolCall(ctx context.Context, resolved *identity.ResolvedIdentity, tool string, arguments map[string]any) toolCallDecision {
	credential := resolved.CredentialID

	if !g.agentLimiter.Allow(resolved.Ref) {
		g.metrics.rateLimited.Inc("agent")
		g.audit(ctx, "gateway.rate_limited", resolved.Ref, fmt.Sprintf("tool=%s credential=%s", tool, credential))
		return toolCallDecision{
			Outcome: outcomeRateLimited,
			Message: "rate limit exceeded for this agent, slow down",
		}
	}

	if g.toolCat != nil {
		if _, err := g.toolCat.Get(ctx, tool); err != nil {
			if errors.Is(err, tools.ErrNotFound) {
				g.metrics.requests.Inc(string(outcomeUnknownTool))
				g.audit(ctx, "gateway.unknown_tool", resolved.Ref, fmt.Sprintf("tool=%s credential=%s", tool, credential))
				return toolCallDecision{Outcome: outcomeUnknownTool, Message: "tool is not registered"}
			}
			// Couldn't determine whether this tool is even real, so this
			// is not a denial, it's "we couldn't ask," worth its own
			// outcome so an incident review can tell it apart from "we
			// said no."
			g.metrics.requests.Inc(string(outcomeToolLookupError))
			g.audit(ctx, "gateway.tool_lookup_error", resolved.Ref, fmt.Sprintf("tool=%s err=%v", tool, err))
			return toolCallDecision{Outcome: outcomeToolLookupError, Message: err.Error(), Err: err}
		}
	}

	allowed, err := g.pol.Check(ctx, resolved.Ref, policy.GrantForTool(tool))
	if err != nil {
		g.metrics.requests.Inc(string(outcomeCheckError))
		g.audit(ctx, "gateway.check_error", resolved.Ref, fmt.Sprintf("tool=%s err=%v", tool, err))
		return toolCallDecision{Outcome: outcomeCheckError, Message: err.Error(), Err: err}
	}
	if !allowed {
		g.metrics.requests.Inc(string(outcomeDeniedTool))
		g.audit(ctx, "gateway.denied", resolved.Ref, fmt.Sprintf("tool=%s credential=%s", tool, credential))
		return toolCallDecision{Outcome: outcomeDeniedTool, Message: "agent is not authorized for this tool"}
	}

	// Being allowed to call the tool is not being allowed to touch every
	// resource the arguments name, see resources.go.
	var resources []string
	if g.resourcePolicy != nil {
		resources = g.resourcePolicy.Resources(tool, arguments)
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
				g.metrics.requests.Inc(string(outcomeCheckError))
				g.audit(ctx, "gateway.check_error", resolved.Ref, fmt.Sprintf("tool=%s resource=%s err=%v", tool, resource, err))
				return toolCallDecision{Outcome: outcomeCheckError, Message: err.Error(), Err: err, Resources: resources}
			}
			if !dataAllowed {
				g.metrics.requests.Inc(string(outcomeDeniedResource))
				g.audit(ctx, "gateway.denied", resolved.Ref, fmt.Sprintf("tool=%s resource=%s level=%s credential=%s", tool, resource, level, credential))
				return toolCallDecision{
					Outcome:   outcomeDeniedResource,
					Message:   fmt.Sprintf("agent is not authorized for resource %q", resource),
					Resources: resources,
				}
			}
		}
	}

	g.metrics.requests.Inc(string(outcomeAllowed))
	g.audit(ctx, "gateway.allowed", resolved.Ref, fmt.Sprintf("tool=%s credential=%s", tool, credential))

	decision := toolCallDecision{Allowed: true, Outcome: outcomeAllowed, Resources: resources}
	if g.monitor != nil {
		if ri, ok := g.observe(ctx, resolved.Ref, tool, resources); ok {
			decision.Risk = &ri
		}
	}
	return decision
}
