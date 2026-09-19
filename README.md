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

This is a real transcript, `niactl simulate attack -scenario agent-hijack` run against the Docker stack below: real `nia-api` and `nia-gateway` processes, a real Tessera instance backed by a real OpenFGA, and one Postgres shared between them. An invoice-processing agent is granted seven tools up front, a realistic, coarse, over-privileged starting point: broad RBAC says yes to all of it. Every call the agent is allowed to make below is fully authorized. Nothing here is an authorization failure. The compromise is visible only in the pattern.

```
[01] agent:invoice-agent -> invoice.read
     ALLOWED
     risk this call: 1, cumulative: 1  [novel_tool(+1)]
[02] agent:invoice-agent -> customer.read
     ALLOWED
     risk this call: 2, cumulative: 2  [novel_tool(+1), novel_transition(+0)]
[03] agent:invoice-agent -> payment.lookup
     ALLOWED
     risk this call: 2, cumulative: 4  [novel_tool(+1), novel_transition(+0)]  monitoring action: flag
[04] agent:invoice-agent -> customer.export
     DETECTED: new tool, privilege deviation (call was allowed, flagged for review, not blocked outright)
     risk this call: 4, cumulative: 8  [novel_tool(+1), novel_transition(+0), risk_class:destructive(+3)]  monitoring action: flag
[05] agent:invoice-agent -> credential.read
     DETECTED: privilege escalation attempt (call was allowed, flagged for review, not blocked outright)
     risk this call: 4, cumulative: 0  [novel_tool(+1), novel_transition(+0), risk_class:destructive(+3)]  monitoring action: kill
[06] agent:invoice-agent -> database.query
     CUT OFF (the credential was revoked by the containment above, this call fails at authentication and never reaches the authorization check)
[07] agent:invoice-agent -> external.upload
     CUT OFF (the credential was revoked by the containment above, this call fails at authentication and never reaches the authorization check)
[08] agent:invoice-agent -> invoice.read
     CUT OFF (the credential was revoked by the containment above, this call fails at authentication and never reaches the authorization check)
```

Steps 1 through 3 are the agent's normal workload, ordinary tool calls it is authorized for, individually unremarkable. The running total still reaches the flag threshold at step 3, purely from tools this agent had never called before. Step 4 is the first thing that looks wrong on its own, a destructive tool this agent has no history with, and it is still allowed, because `policy.Check` says yes and the grant is real. Step 5 reaches for credentials, crosses the kill threshold, and `internal/monitoring.Monitor` calls `internal/policy.Kill`: a kill sentinel is set in Tessera and the agent's credential is revoked in the same decision. The cumulative total resets to 0, which is the one thing that resets it.

Steps 6 through 8 are what containment actually looks like from the agent's side. It is not that its calls are refused, it is that the credential it was using no longer exists, so it fails at authentication and never reaches the authorization check at all. Step 8 is the same tool as step 1, granted and already used successfully, which is the point: nothing about the request changed, the agent did.

`GET /risk/agent:invoice-agent` on the gateway, read right after this run, shows the same decisions as structured `internal/incident` records rather than just this transcript:

```json
{"cumulative":0,"thresholds":{"FlagAt":4,"RevokeAt":100,"KillAt":12},"incidents":[
  {"Action":"flag","Cumulative":4,"Reason":"cumulative risk 4 crossed threshold"},
  {"Action":"flag","Cumulative":8.5,"Reason":"cumulative risk 8 crossed threshold"},
  {"Action":"kill","Cumulative":13,"Reason":"cumulative risk 13 crossed threshold, killed, revoked 1 active credential(s)"}
]}
```

`GET /metrics` on the gateway from the same run, one more way to see the same eight calls:

```
nia_gateway_requests_total{outcome="allowed"} 5
nia_gateway_requests_total{outcome="unresolved"} 3
nia_monitoring_actions_total{action="flag"} 2
nia_monitoring_actions_total{action="kill"} 1
```

Five allowed, three that could not authenticate because the agent had been contained, two flags and one kill. The thresholds were `NIA_RISK_FLAG_AT=4`, `NIA_RISK_REVOKE_AT=100` and `NIA_RISK_KILL_AT=12`, chosen so the run reaches the kill; set the revoke threshold low instead and containment fires earlier, at the revoke, and the rest of the sequence is cut off the same way. The specific numbers are not the point, a real accumulating total crossing a real threshold is.

## How it works

NIA sits in front of the tools an agent calls, and decides, per call, whether that call happens.

- **Authorization is the floor, not the ceiling.** [Tessera](https://github.com/bogdanticu88/Tessera) and OpenFGA answer "is this agent allowed to call this tool", and NIA reuses them rather than reimplementing relationship-based authorization. Every call in the transcript above was allowed. The compromise was only visible in the pattern across calls, which is the part an authorization engine is not built to see.
- **Identity is bound to a credential, not claimed in a header.** An agent authenticates with a bearer credential or a mutual TLS client certificate whose SHA-256 thumbprint an operator explicitly bound to it. A valid certificate from a trusted CA that is not bound to an agent does not authenticate, because trusting a CA's issuance process is not knowing who is calling.
- **One pipeline, whichever door you come through.** REST at `POST /tools/{tool}/call` and MCP over Streamable HTTP at `POST /mcp` both run the same decision in `cmd/gateway/decision.go`: rate limit, tool catalog, tool grant, resource-level data grants derived from the call's own arguments, audit, then risk. Two front doors with two copies of the pipeline is how one of them quietly ends up missing a check.
- **Risk accumulates across calls, and containment is a real state change.** Crossing a threshold flags, revokes, or kills. A kill sets a sentinel in the policy engine that every process reads live, so a kill decided in one replica is enforced by the next request to any other, with no cache to go stale.
- **The audit trail is hash-chained and externally anchored.** Every decision is recorded, and HMAC-signed checkpoints mean a rewrite that recomputes every hash consistently still fails verification.

The decision completes before anything is forwarded, so a refused call is never sent rather than sent and ignored.

## Quickstart

Needs Go 1.25 and nothing else. Every command below was run against a clean clone of this repository before being written down.

```bash
git clone https://github.com/bogdanticu88/NIA.git && cd NIA
go build ./... && go test ./...

# The control plane refuses to start open, so say so explicitly.
# Listens on :8080.
NIA_ALLOW_UNAUTHENTICATED=1 go run ./cmd/api

# In another terminal, drive it.
go run ./cmd/niactl register -ref agent:billing-reconciler -owner bogdan -purpose "reconciles invoices nightly"
go run ./cmd/niactl tool register -name invoice.read -transport http -risk read_only -owner bogdan
go run ./cmd/niactl grant write -ref agent:billing-reconciler -kind tool -object invoice.read
go run ./cmd/niactl credential issue -ref agent:billing-reconciler -kind api_key -ttl 24h

# What could this agent reach if it were compromised right now
go run ./cmd/niactl graph blast-radius -id agent:billing-reconciler

# Everything that just happened to it
go run ./cmd/niactl audit -ref agent:billing-reconciler
```

That is the control plane on its own, and it needs no infrastructure because every store falls back to an in-memory implementation when its environment variable is unset.

What it cannot do is the transcript above. The gateway is a separate process, and with the in-memory defaults each process keeps its own private state, so a credential issued through `cmd/api` is invisible to `cmd/gateway` and every call it makes comes back 401. That is not a bug to work around, it is the two processes genuinely having nothing shared to check against. Running the gateway for real means giving them a shared backend, which is what the Docker stack below is for.

## Running the full stack

Needs Docker and [Tessera](https://github.com/bogdanticu88/Tessera) checked out as a sibling directory, since compose builds it from `../../tessera`.

```bash
cd deployments

# 1. The two files a fresh clone does not ship, because both hold secrets.
cp operator-tokens.example.json operator-tokens.json   # then replace every token in it
cat > .env <<'ENV'
NIA_TESSERA_JWT_SIGNING_KEY=<openssl rand -base64 32>
TESSERA_OPENFGA_STORE_ID=placeholder
NIA_TOOLS_API_TOKEN=<the viewer token from operator-tokens.json>
ENV

# 2. OpenFGA has no store until it is running, so bootstrap it first.
#    TESSERA_OPENFGA_STORE_ID needs a placeholder value before this:
#    compose interpolates every service's variables even when you name
#    only two, so a missing one fails the command outright.
docker compose up -d postgres openfga
./bootstrap-openfga.sh          # prints the real store id

# 3. Put that id in .env, replacing the placeholder, then bring up the rest.
docker compose up -d --build
```

Five containers, all healthy: `nia-api`, `nia-gateway`, `tessera`, `openfga`, `postgres`. Both NIA services share one Postgres for credentials, audit, registry, incidents and risk state, and one Tessera for policy, which is what makes the gateway usable.

One thing to know before it bites you: OpenFGA here keeps its store in memory, so recreating that container throws away the store and the authorization model while `.env` still names the old id. Everything then fails with a Tessera 500 whose real cause, `No authorization models found for store`, is only visible in `docker compose logs tessera`. Re-run `./bootstrap-openfga.sh`, put the new id in `.env`, and bring the stack up again.

Risk monitoring is off by default, deliberately, since a kill threshold in a shared dev stack is the kind of thing that should be opted into rather than sprung on someone. Three lines in `.env` turn it on:

```bash
NIA_RISK_FLAG_AT=4
NIA_RISK_REVOKE_AT=100
NIA_RISK_KILL_AT=12
```

Then `docker compose up -d nia-gateway` and:

```bash
export NIA_OPERATOR_TOKEN=<the admin token from operator-tokens.json>
go run ./cmd/niactl simulate attack -scenario agent-hijack
```

Worth knowing before you read the output: revoke and kill both genuinely revoke the agent's credential now, so once containment fires, every later call in the sequence returns 401 rather than continuing. The thresholds above are chosen to reach the kill; set `NIA_RISK_REVOKE_AT` low instead and the run ends earlier, at the revoke. Either way the agent is cut off partway through its own attack, which is the thing being demonstrated.

[`docs/RUNNING.md`](docs/RUNNING.md) has the full `niactl` command tour and the rest of the environment variables.

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
