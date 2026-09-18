# NIA and the Model Context Protocol

What NIA actually implements of MCP, what it deliberately does not, and what a deployment has to know before putting an agent behind it. Every claim here was checked against a running gateway with a real downstream MCP server, not read off the SDK's documentation, and where something was verified by probe the probe is named.

The implementation is `cmd/gateway/mcp.go`, built on `github.com/modelcontextprotocol/go-sdk` v1.8.0. That SDK's newest protocol version is `2026-07-28`, and it also speaks `2025-11-25`, `2025-06-18`, `2025-03-26` and `2024-11-05`. NIA does not pin a version: it advertises what the SDK supports and negotiates per request, confirmed by a `server/discover` response listing all five.

* * *

## Transport

Streamable HTTP at `POST /mcp`, stateless, and that is the only transport.

Stateless means each POST is its own server session. No session id is issued and none is required, verified by probe: a `tools/call` returns no `Mcp-Session-Id` header, and the same credential's next call is served with no reference to the first. That is what makes the gateway safe behind a load balancer with no sticky routing, and it is also why there is no process-local state to go stale when a replica is replaced.

Deliberately not implemented:

- **stdio.** NIA authenticates a network peer and audits it. A process on the same machine speaking over pipes is a different trust boundary with a different answer to "who is calling", and half of that is worse than none.
- **The legacy HTTP+SSE transport as a primary path.** The SDK still accepts older protocol versions over Streamable HTTP, which is the compatibility that matters. A second transport would be a second door into the same decision, and the point of `decision.go` is that there is only one.
- **The standalone SSE stream to the client.** A stateless session has nowhere to deliver a server-initiated message after the response, so `DisableStandaloneSSE` is set on the downstream connection too.
- **Resumability.** Event replay needs a session to resume into.

Transport behaviour, all confirmed by probe against a running gateway: a GET to `/mcp` is refused 405, a POST with the wrong content type 415, a POST with no credential 401, a POST with a bad credential 401. Authentication happens in the HTTP handler in front of the MCP machinery, so an unauthenticated caller never reaches the protocol parser.

## Lifecycle

Two handshakes exist, and which one a client uses depends on the version it speaks.

Clients on `2025-11-25` and older send `initialize`. That method routes through NIA's receiving middleware and is audited as `gateway.mcp_initialize`.

From `2026-07-28` `initialize` is deprecated and the handshake is `server/discover`, which routes through the same middleware and is audited as `gateway.mcp_method` with `method=server/discover`. Both were verified by sending each one at a running gateway and reading the audit trail back. An earlier version of this repo claimed the SDK handled `initialize` internally and never surfaced it to middleware; that was wrong, and the phase 33 audit corrected it. What is true is that a modern client never sends `initialize` at all, which is why it looked that way.

From `2026-07-28` the SDK also requires `Mcp-Method` and, for tool operations, `Mcp-Name` headers that agree with the JSON-RPC body, and answers a mismatch with error `-32020`. Those headers are a transport hint. NIA authorizes the tool named in the body, never the one named in the header, which was verified as a matrix: header names a granted tool and the body an ungranted one, the call is denied; header names an ungranted tool and the body a granted one, the call is allowed. The tool that would have been smuggled through was never executed once.

## What NIA proxies

`tools/call` and `tools/list`, and nothing else.

`tools/call` is the operation with a side effect and it runs the full pipeline in `cmd/gateway/decision.go`, the same one the REST front door uses: per-agent rate limit, tool catalog check, tool grant, resource-level data grants derived from the arguments, audit, then risk scoring and containment. The decision completes before the downstream connection is opened, so a refused call is never sent rather than sent and ignored. Arguments that cannot be decoded are refused rather than forwarded, because an operation NIA cannot read is one it cannot authorize.

`tools/list` reports what the downstream offers, not what the calling agent may call, so an agent can see the name of a tool it would be refused. That is a deliberate choice, not an oversight. Filtering the list to the agent's grants is defensible and is a real option, but it changes what an agent sees rather than what it can do, and it would also mean a tool an agent is refused becomes invisible rather than visibly denied, which is harder to debug and easier to misread as "the tool is gone." The exposure is a tool name and its schema, which is the same information an operator's catalog holds.

The downstream connection is NIA's own: a separate MCP session, opened per operation, authenticated with NIA's own credential if one is configured. The agent's bearer credential authenticates the agent to NIA and stops there. It is never forwarded, because a downstream holding it could act as that agent against anything else that trusts the same credential.

Responses come back through `inspectMCPResult`, which audits size and error status and runs the same sensitive-field check the REST path runs. It is not a DLP engine and does not try to be.

## What the SDK answers locally

NIA's middleware sees every dispatched method and audits it, but methods other than `tools/call` and `tools/list` are passed to the SDK rather than refused. None of them reaches the downstream. What they do locally, confirmed by probe:

| Method | Behaviour through NIA |
| --- | --- |
| `resources/list`, `prompts/list` | Answered locally with an empty list. NIA registers no resources or prompts and does not proxy the downstream's. |
| `resources/read`, `completion/complete` | Dispatched, then fail in the SDK because nothing is registered. |
| `logging/setLevel`, `ping` | `-32601` method not found, the server does not declare them. |
| `roots/list`, `sampling/createMessage`, `elicitation/create` | `-32601`. These are server-to-client calls; a client sending them gets nothing. |
| `subscriptions/listen` | Answered locally, acknowledges the subscription and holds an SSE stream open until the client goes away. NIA emits none of the notifications it subscribes to, so the stream stays empty. |
| `notifications/cancelled` | Accepted with 202 and has no effect, see below. |
| `tasks/*` | `-32601`. Not implemented by SDK v1.8.0 at all. |

`subscriptions/listen` is the one worth stating plainly: an authenticated agent can hold open as many of those streams as it can open connections, and NIA applies no per-agent cap to them. Twenty-five concurrent streams from one credential were held with no refusal. The per-agent rate limit lives inside the tool-call decision, so it does not apply. The sockets are released when the client disconnects, so this is a resource-holding surface rather than a leak, and it requires a valid credential, so it is an availability concern rather than an authorization one. Narrowing the dispatched surface to the methods NIA actually serves would close it and is the obvious next change; it is not made here because it changes what the endpoint answers, which is a deployment-visible behaviour change rather than a bug fix.

## Cancellation

Neither form of cancellation reaches the downstream today. Both were tested against a downstream tool that blocks for eight seconds and logs whether it completed or was cancelled.

An agent that disconnects mid-call does not cancel anything: the tool ran to completion and logged its side effect, one second after the client was gone. The SDK gates that behaviour behind `PropagateRequestCancellation`, which defaults to false and which NIA does not set.

A `notifications/cancelled` sent as a separate POST is accepted with 202 and does nothing. In the SDK, cancellation is a preempter on the JSON-RPC connection carrying the in-flight call; in stateless Streamable HTTP each POST is its own connection, so a notification arriving on a second POST has no in-flight request to cancel. This is a property of the stateless session model, not something NIA suppresses.

The security consequence is small but should be stated rather than assumed: a cancelled call is still a call that happened. NIA audits it as allowed and as completed, and the risk score counts it, which is the correct record of what the downstream actually did.

Enabling `PropagateRequestCancellation` would make the first form work and is the obvious improvement. It needs care rather than a flag flip: NIA's audit writes run on the request context, so tying that context to the client's connection would mean a client that hangs up mid-decision could cancel the audit write for the decision that was just made. Auditing on a context that outlives the request is the prerequisite.

## Tasks

The `2026-07-28` specification adds Tasks, the augmentation that lets a long-running request be tracked and polled rather than held open. SDK v1.8.0 does not implement them: there is no `tasks/` method in its protocol definitions, and a client asking for one gets `-32601`.

NIA does not implement them either, and should not implement them ahead of the SDK. A hand-rolled task layer would be NIA inventing a protocol feature its own client library does not speak, which is how two implementations of the same spec end up disagreeing about what a task id means. When the SDK gains Tasks, the security question to answer first is which identity a task result belongs to, because a task outlives the request that created it and therefore outlives the request's authentication.

## Security model on this path

Unchanged from the REST path, on purpose. `decision.go` holds the pipeline once and both front doors call it, so there is no MCP-specific authorization path that could be missing a control. The invariants in docs/SECURITY_INVARIANTS.md apply here as written: credential-bound identity, kill state read live from the policy engine rather than cached in the process, the hash-chained audit trail, and containment that can revoke or kill mid-sequence.

Two things this path adds to the audit trail: `gateway.mcp_request`, one line per authenticated request, written at the transport layer so that requests refused before dispatch still leave an attributable trace, and the per-method lines above. A request that is rejected for a bad header or an unknown method produces the transport line only, which is correct, it never became an operation.
