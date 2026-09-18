# NIA: Non-Human Identity & Agent Security

[![Non-Human Identity](https://img.shields.io/badge/Non--Human%20Identity-2b2d42)](docs/ARCHITECTURE.md)
[![Agent Security](https://img.shields.io/badge/Agent%20Security-2b2d42)](docs/ARCHITECTURE.md)
[![OpenFGA / ReBAC](https://img.shields.io/badge/OpenFGA-ReBAC-2b2d42)](https://openfga.dev)
[![CI](https://github.com/bogdanticu88/NIA/actions/workflows/ci.yml/badge.svg)](https://github.com/bogdanticu88/NIA/actions/workflows/ci.yml)
[![Go version](https://img.shields.io/github/go-mod/go-version/bogdanticu88/NIA)](go.mod)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A runtime security control plane for AI agents: know what an agent is allowed to do, who authorised it, what it actually did, watch what it does after that, and stop it in the next second instead of the next deploy. Authorization is the floor, not the ceiling, an agent can be fully authorized for everything it does on the way to a compromise, see the transcript below.

NIA generalizes [Tessera](https://github.com/bogdanticu88/tessera), a relationship-based authorization control plane built on [OpenFGA](https://openfga.dev), from "M2M API client" to "AI agent." Tessera's live per-request checks and surgical kill switch aren't rebuilt here, they're reused as the policy engine layer. On top of that, NIA adds the parts an authorization control plane alone doesn't cover: a risk score that accumulates across a sequence of individually-authorized calls, runtime monitoring that flags, revokes, or kills when that score crosses a threshold, structured incident evidence for what triggered a containment decision, an identity graph for blast-radius analysis, and agent registration, credential lifecycle, and tool/MCP awareness underneath all of it.

Full documentation is in [`docs/`](docs/), and the development log is in [`CHANGELOG.md`](CHANGELOG.md). See the [Documentation](#documentation) section below for what each file covers.

## See it work

This is a real transcript, `niactl simulate attack -scenario agent-hijack` run against real `nia-api` and `nia-gateway` processes sharing a real, running Tessera instance (in-memory-backed, no OpenFGA needed for this), not printed output standing in for one. An invoice-processing agent is granted seven tools up front, a realistic, coarse, over-privileged starting point: broad RBAC says yes to all of it. Each individual call below is fully authorized. Nothing here is an authorization failure. The compromise is visible only in the pattern:

```
[01] agent:invoice-agent -> invoice.read
     ALLOWED
     risk this call: 1, cumulative: 1  [novel_tool(+1)]
[02] agent:invoice-agent -> customer.read
     ALLOWED
     risk this call: 1, cumulative: 2  [novel_tool(+1)]
[03] agent:invoice-agent -> payment.lookup
     ALLOWED
     risk this call: 1, cumulative: 3  [novel_tool(+1)]
[04] agent:invoice-agent -> customer.export
     DETECTED: new tool, privilege deviation (call was allowed, flagged for review, not blocked outright)
     risk this call: 4, cumulative: 7  [novel_tool(+1), risk_class:destructive(+3)]  monitoring action: flag
[05] agent:invoice-agent -> credential.read
     DETECTED: privilege escalation attempt (call was allowed, flagged for review, not blocked outright)
     risk this call: 4, cumulative: 11  [novel_tool(+1), risk_class:destructive(+3)]  monitoring action: revoke
[06] agent:invoice-agent -> database.query
     DETECTED: sensitive data access (customers.ssn) (call was allowed, flagged for review, not blocked outright)
     risk this call: 1, cumulative: 12  [novel_tool(+1)]  monitoring action: revoke
[07] agent:invoice-agent -> external.upload
     DETECTED: exfiltration attempt (call was allowed, flagged for review, not blocked outright)
     risk this call: 4, cumulative: 0  [novel_tool(+1), risk_class:destructive(+3)]  monitoring action: kill
[08] agent:invoice-agent -> invoice.read
     BLOCKED (agent is not authorized for this tool)
```

Steps 1 through 3 are the agent's normal workload, ordinary tool calls it's authorized for, low risk, nothing worth a second look. Step 4 is the first sign something changed, a destructive tool this agent has never called before, flagged, not blocked, `policy.Check` still says yes because the grant is real. Step 5 pushes the running total over the revoke threshold, an actual `internal/monitoring` containment decision, not a log line, though in this run it's an audited no-op, `cmd/gateway` has no `credentials.Store` wired into it, a documented, honest gap, see `docs/ARCHITECTURE.md`'s Runtime monitoring row. Step 7 crosses the kill threshold: `internal/monitoring.Monitor` calls `internal/policy.Kill`, a real kill sentinel gets set in Tessera, and the cumulative risk resets to 0, the one thing that does reset it. Step 8 re-calls a tool the agent was granted and had already used successfully in step 1, and it's denied, not because anything about the request changed, but because `policy.Check` now reads the kill sentinel instead of the prior grant. That's an actual state transition an incident responder could have triggered by hand with `niactl kill`, except here nothing human decided it, the accumulated pattern did.

`GET /risk/agent:invoice-agent` on the gateway, read right after this run, shows the same four containment decisions as structured `internal/incident` records, not just this transcript:

```json
{"cumulative":0,"thresholds":{"FlagAt":4,"RevokeAt":8,"KillAt":15},"incidents":[
  {"Action":"flag","Cumulative":7,"Reason":"cumulative risk 7 crossed threshold"},
  {"Action":"revoke","Cumulative":11,"Reason":"cumulative risk 11 crossed the revoke threshold, but this process has no credentials.Store configured, nothing was revoked"},
  {"Action":"revoke","Cumulative":12,"Reason":"cumulative risk 12 crossed the revoke threshold, but this process has no credentials.Store configured, nothing was revoked"},
  {"Action":"kill","Cumulative":16,"Reason":"cumulative risk 16 crossed threshold"}
]}
```

`GET /metrics` on the gateway from the same run: `nia_gateway_requests_total{outcome="allowed"} 7`, `nia_gateway_requests_total{outcome="denied_tool"} 1`, `nia_monitoring_actions_total{action="flag"} 1`, `nia_monitoring_actions_total{action="revoke"} 2`, `nia_monitoring_actions_total{action="kill"} 1`, the same eight-call sequence, one more way to see it.

One honest gap this specific run surfaced, and what happened to it since, because the transcript above predates the fix: `niactl agent inspect`, read right after the kill, used to still show the agent's `state` as `active`. The kill went through `internal/monitoring.Monitor` calling `internal/policy.Kill` directly inside `cmd/gateway`, which is what actually revokes access, but it never touched `cmd/api`'s own registry, so the control plane's inventory could report an agent as active that was, in every way that mattered to the gateway, already killed. Enforcement was never wrong, step 8 above proves the next call is genuinely denied, but the inventory disagreed with it. That is closed now, and not the way this README originally predicted: rather than having `cmd/gateway` reach back into `cmd/api` over HTTP on every automatic kill, `GET /agents/{ref}` queries the live kill sentinel on every read and reports it as `effective_state`, with `kill_sentinel_checked` saying whether that live query itself succeeded, so a cached `state` can look stale for a moment but `effective_state` cannot be wrong without saying so. See phases 13 and 26 in [`CHANGELOG.md`](CHANGELOG.md).

Reproducing this: bring up `nia-api` and `nia-gateway` both pointed at the same Tessera instance (`NIA_TESSERA_BASE_URL` and the signing key, see [`docs/RUNNING.md`](docs/RUNNING.md)), start the gateway with `NIA_RISK_FLAG_AT=4 NIA_RISK_REVOKE_AT=8 NIA_RISK_KILL_AT=15` and `NIA_TOOLS_API_URL` pointed at `nia-api` (so the `risk_class` signal is scored, not just `novel_tool`), then `niactl simulate attack -scenario agent-hijack`. Lower or higher thresholds change exactly where flag/revoke/kill fire, the point isn't the specific numbers, it's that they're real thresholds being crossed by a real accumulating total, not a scripted outcome.

## How it works

NIA sits in front of the tools an agent calls, and decides, per call, whether that call happens.

- **Authorization is the floor, not the ceiling.** [Tessera](https://github.com/bogdanticu88/Tessera) and OpenFGA answer "is this agent allowed to call this tool", and NIA reuses them rather than reimplementing relationship-based authorization. Every call in the transcript above was allowed. The compromise was only visible in the pattern across calls, which is the part an authorization engine is not built to see.
- **Identity is bound to a credential, not claimed in a header.** An agent authenticates with a bearer credential or a mutual TLS client certificate whose SHA-256 thumbprint an operator explicitly bound to it. A valid certificate from a trusted CA that is not bound to an agent does not authenticate, because trusting a CA's issuance process is not knowing who is calling.
- **One pipeline, whichever door you come through.** REST at `POST /tools/{tool}/call` and MCP over Streamable HTTP at `POST /mcp` both run the same decision in `cmd/gateway/decision.go`: rate limit, tool catalog, tool grant, resource-level data grants derived from the call's own arguments, audit, then risk. Two front doors with two copies of the pipeline is how one of them quietly ends up missing a check.
- **Risk accumulates across calls, and containment is a real state change.** Crossing a threshold flags, revokes, or kills. A kill sets a sentinel in the policy engine that every process reads live, so a kill decided in one replica is enforced by the next request to any other, with no cache to go stale.
- **The audit trail is hash-chained and externally anchored.** Every decision is recorded, and HMAC-signed checkpoints mean a rewrite that recomputes every hash consistently still fails verification.

The decision completes before anything is forwarded, so a refused call is never sent rather than sent and ignored.

## Quickstart

Needs Go 1.25. No Postgres, Tessera or OpenFGA required for this.

```bash
# 1. build and check
go build ./... && go test ./...

# 2. start the control plane and the gateway, in two terminals
go run ./cmd/api
go run ./cmd/gateway

# 3. drive the whole loop: registration, grants, and a scripted attack sequence
go run ./cmd/niactl simulate attack -scenario agent-hijack
```

To reproduce the transcript above with real containment firing, the gateway needs risk thresholds and both processes need a shared policy backend, since each one otherwise keeps its own private in-memory state and every gateway call is denied for a genuinely empty reason. [`docs/RUNNING.md`](docs/RUNNING.md) has the exact environment variables, the full `niactl` command tour, and the Docker Compose stack with its OpenFGA bootstrap step.

## Layout

```
cmd/api        control-plane API: registration, inventory, credentials, grants, kill switch
cmd/gateway    Agent/MCP gateway: the hot path, resolve -> check -> forward
cmd/niactl     operator CLI, talks to cmd/api over HTTP (and cmd/gateway directly for gateway call / simulate attack)
internal/      identity, registry, credentials, policy, audit, risk, monitoring, incident, graph, metrics
deployments/   Dockerfiles, docker-compose, and the OpenFGA store/model bootstrap for local dev
docs/          architecture, data model, threat model, and security invariants
```

## Documentation

| File | What's in it |
| --- | --- |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | The design, the seventeen-item MVP-to-module map, and the distributed-state table saying which state is shared across replicas and which is not |
| [`docs/SECURITY_INVARIANTS.md`](docs/SECURITY_INVARIANTS.md) | Each guarantee as a checkable claim, with the test that checks it named, and fail-open behaviour called fail-open |
| [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) | Per-threat Prevent/Detect/Contain/Investigate breakdown, including what is explicitly not covered |
| [`docs/MCP.md`](docs/MCP.md) | Exactly what the MCP endpoint implements of the `2026-07-28` specification, and what it deliberately does not |
| [`docs/DATA_MODEL.md`](docs/DATA_MODEL.md) | The identity graph schema |
| [`docs/RUNNING.md`](docs/RUNNING.md) | Full local setup, every CLI command, and the two-process gotchas |
| [`CHANGELOG.md`](CHANGELOG.md) | The development log, one entry per phase, each ending in what was actually run to verify it |

## Status

Released as [v0.1.0](https://github.com/bogdanticu88/NIA/releases/tag/v0.1.0). The version is 0.x deliberately: the configuration surface and the Go package boundaries are still open to change.

610 tests across 17 packages, run with `-race` in CI on every push against a real Postgres service, with CI asserting that the Postgres-backed tests actually executed rather than skipped. Beyond the suite, the security-critical paths were each run at least once against real infrastructure: a real Tessera service, real OpenFGA, real Postgres, and a real downstream MCP server. [`CHANGELOG.md`](CHANGELOG.md) records what was verified, phase by phase, and how.

Three limitations are open and documented rather than implied:

- The identity graph is in-memory and process-local, so it is lost on restart and diverges across replicas. It stays evidentiary, nothing on the authorization path reads it.
- Tool catalog enforcement assumes a single `cmd/api` replica. It fails closed, a miss is a denial and never an allow.
- MCP cancellation does not propagate, so a cancelled call still reaches the downstream and is audited as the call it was.

## License

[MIT](LICENSE).
