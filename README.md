# NIA: Non-Human Identity & Agent Security

[![Non-Human Identity](https://img.shields.io/badge/Non--Human%20Identity-2b2d42)](docs/ARCHITECTURE.md)
[![Agent Security](https://img.shields.io/badge/Agent%20Security-2b2d42)](docs/ARCHITECTURE.md)
[![OpenFGA / ReBAC](https://img.shields.io/badge/OpenFGA-ReBAC-2b2d42)](https://openfga.dev)
[![CI](https://github.com/bogdanticu88/NIA/actions/workflows/ci.yml/badge.svg)](https://github.com/bogdanticu88/NIA/actions/workflows/ci.yml)
[![Go version](https://img.shields.io/github/go-mod/go-version/bogdanticu88/NIA)](go.mod)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

An agent security control plane: know what an agent is allowed to do, who authorised it, what it actually did, and how to stop it, in the next second instead of the next deploy.

NIA generalizes [Tessera](https://github.com/bogdanticu88/tessera), a relationship-based authorization control plane built on [OpenFGA](https://openfga.dev), from "M2M API client" to "AI agent." Tessera's live per-request checks and surgical kill switch aren't rebuilt here, they're reused as the policy engine layer. NIA adds agent registration, credential lifecycle, tool and MCP awareness, risk scoring, runtime monitoring, agent-to-agent trust, delegation, and an identity graph on top.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full design and the seventeen-item MVP-to-module map, and [`docs/DATA_MODEL.md`](docs/DATA_MODEL.md) for the identity graph schema.

## Status

Package boundaries, interfaces, and in-memory reference implementations exist for every one of the seventeen MVP components. `internal/policy` additionally has a second, real implementation, `TesseraHTTPClient`, that drives an actual Tessera.Service instance over HTTP instead of the in-memory reference. `cmd/api` and `cmd/gateway` pick between the two at startup based on environment (`policy.FromEnv`, unset `NIA_TESSERA_BASE_URL` means the in-memory one, same "runs out of the box" default as before).

What's actually been verified, and how:

- `internal/policy`: unit tests against a fake HTTP server (network failures, malformed and oversized responses, cancellation, concurrent writers) plus a live test that spawns a real `Tessera.Service` process and drives it over actual HTTP (`internal/policy/tessera_client_live_test.go`, opt-in via `NIA_TESSERA_REPO_PATH`, a checked-out Tessera repo with `src/Tessera.Service` already built).
- `cmd/api` and `cmd/gateway` against that same real `Tessera.Service` process, driven over real HTTP end to end, not just through Go's own test harness: registered an agent, killed it through `POST /policy/kill`, and confirmed Tessera's own state showed the kill. This is what caught a real bug (an agent ref containing `:`, NIA's own convention, `agent:billing-reconciler`, fails Tessera's `client_ref` validation outright) that no unit test had a reason to exercise, since none of them used a ref in that shape. Fixed with a reversible encoding at the `TesseraHTTPClient` boundary, see its doc comment, point 5.

- `deployments/docker-compose.yml`, on a real Docker daemon: all five containers (`nia-api`, `nia-gateway`, `tessera`, `openfga`, `postgres`) built and came up healthy, then a client was onboarded through Tessera's real HTTP surface, checked as allowed directly against OpenFGA, killed, and checked again as denied, actual tuples written to and deleted from a real OpenFGA store, not the in-memory one. `deployments/bootstrap-openfga.sh` creates the store and loads the authorization model this needs, see the comment at the top of `docker-compose.yml`. This run caught two more real bugs in Tessera's OpenFGA adapter, both fixed: `IAuthorizationStore` wasn't resolving through dependency injection when pointed at a real store, and `ReadTuplesForClientAsync` filtered OpenFGA's read endpoint by user alone, which OpenFGA rejects outright. Neither the harness tests nor the earlier live test against Tessera's in-memory store had a reason to catch either, only a real OpenFGA instance exercises that code path. See Tessera's own commit history on `feature/openfga-http-adapter` for both fixes.

What has not: `Dockerfile.api` and `Dockerfile.gateway` build correctly for `linux/arm64` and standard `linux/amd64` hosts, unconfirmed on anything more exotic. Multi-replica behavior (more than one `nia-api` or `tessera` instance against the same store) hasn't been exercised, the read-modify-write races that implies are a documented, open gap, see `internal/policy/tessera_client.go`'s doc comment.

- `internal/audit`: the gateway now writes every decision it makes (`gateway.allowed`, `gateway.denied`, `gateway.check_error`) to the audit trail, not just `cmd/api`'s own registration and kill events, closing a gap where the package's own doc comment promised "aggregates events from the gateway" and nothing in the gateway actually did that. `cmd/api` exposes it over HTTP (`GET /audit`, `GET /agents/{ref}/audit`) and `niactl audit` wraps both. Verified with `go test ./... -race` (unit tests for `InMemorySink`'s ordering and eviction, and for both HTTP handlers, including that an unresolved caller correctly produces no event, there's no subject to attach one to) and with a live run: real `nia-api` and `nia-gateway` binaries, driven over actual HTTP by `niactl` and `curl`, registering an agent, calling the gateway both with and without a valid identity header, killing the agent, and reading the result back through `niactl audit -ref`. That live run also confirmed a real limitation head on rather than just asserting it, which is what motivated the next item below: `nia-api` and `nia-gateway` each held their own in-memory sink, so a gateway decision was invisible to `niactl audit`, which only talks to `cmd/api`.

- `internal/audit.PostgresSink`: a real, shared `Store` backing the trail, `database/sql` plus `lib/pq`, schema created on first connect (`CREATE TABLE IF NOT EXISTS`, see `postgres_sink.go`, this table's shape has never changed and doesn't warrant a migration framework yet). `audit.FromEnv` picks it over `InMemorySink` when `NIA_AUDIT_DATABASE_URL` is set, same pattern as `policy.FromEnv`, and `deployments/docker-compose.yml` points both NIA services at the stack's own `postgres` service so they share one trail instead of two. Written somewhere with no network path to the Go module proxy, so it went through three separate confirmations once real internet was available rather than one: `go mod tidy && go build ./... && go vet ./... && go test ./... -race` (clean, including the new code's first real compile), the opt-in live test against a standalone `postgres` container (`NIA_AUDIT_TEST_DATABASE_URL=... go test ./internal/audit/... -run TestPostgresSink_Live -v`, confirms inserts and both read paths against a real database), and the full `docker compose up -d --build` stack, registered an agent through `nia-api`, called `nia-gateway` with no grants yet (denied), killed the agent, then read `GET /agents/{ref}/audit` back from `nia-api` and got `agent.registered`, `gateway.denied`, `agent.killed`, all three, correctly ordered, one process reading back what another process wrote. That last part is the actual point: the two services now genuinely share one audit trail instead of each keeping its own.

- `internal/credentials`: the package already had a full in-memory `Store`, issue, get, list, revoke, but nothing outside the package called it. `cmd/api` exposes it now, `POST /agents/{ref}/credentials` to issue, `GET` to list, `POST /credentials/{id}/revoke` to retire one, and `niactl credential issue` / `list` / `revoke` wrap all three. Issuing requires the agent to already be registered, revoking writes `credential.revoked` to the audit trail the same way every other control-plane action does, so `niactl audit -ref` now shows a credential's whole lifecycle next to registration and kills. Verified with `go test ./... -race`, seven new tests on the in-memory store and six on the HTTP handlers. `cmd/api` has no network path to the Go module proxy in the environment this was written in either, same constraint `PostgresSink` hit, so the whole module was verified once against a local stub of the `lib/pq` import path (nothing committed, no network involved) to get a real build/vet/test pass rather than a hand review of the new code.

- `internal/registry/tools`: same gap, same fix. `cmd/api` now exposes the catalog, `POST /tools` to register, `GET /tools` and `GET /tools/{name}` to read it back, `niactl tool register` / `list` / `get` on top. Registering defaults `risk_class` to `read_only` rather than requiring it, and rejects anything else that isn't `read_only`, `write`, or `destructive`. Verified with `go test ./... -race`, six new tests on the HTTP handlers, same build-verification path as the credentials work above.

- Closing the gap the item above left open on purpose: the gateway now actually consults the tool catalog. Set `NIA_TOOLS_API_URL` (`cmd/api`'s own address) and `handleToolCall` looks the tool up over HTTP, `tools.HTTPReader`, before ever reaching the policy check, 404s outright if nobody registered it, and writes `gateway.unknown_tool` to the audit trail. Unset, this step is skipped entirely, the gateway's original tool-name-only behavior is unchanged, additive rather than a stricter default nothing opted into. The lookup goes back to `cmd/api` over HTTP rather than a second shared store, the same tradeoff the audit trail made before `PostgresSink`, except here a tool's existence changes rarely enough relative to the hot path's actual bottleneck (the policy check) that this is the whole answer, not a stopgap. A lookup error (not "unregistered", "couldn't ask") is treated the same way a failed policy check already was: audited separately, 500, not let through. Verified with `go test ./... -race`, four new tests on `HTTPReader` against a real `httptest.Server`, three on `FromEnvReader`, and three more on the gateway's handler (unknown tool short-circuits before `Check` is ever called, a registered tool proceeds normally, a lookup error is audited and blocked), same build-verification path as everything else in this section.

- `internal/risk` and `internal/monitoring` moved past their own stubs. `risk.HistoryScorer` is the first real `Scorer`, two signals computed without any external dependency: `novel_tool` (has this agent ever called this exact tool before, tracked in process memory) and, when the tool catalog is configured, `risk_class` (weighted by how destructive the tool is, sharing the same `tools.Reader` the gateway's catalog check already uses). `internal/monitoring.Monitor` had a real bug fixed along the way: `ActionRevoke`'s own doc comment promised "one credential revoked" and the code never revoked anything, it just wrote an audit event. It now actually revokes, every active credential belonging to the agent via `credentials.Store` (not a single key, there's no per-call credential attribution in this scaffold to revoke just one, see the doc comment on `revokeCredentials`), and reports plainly in the audit detail when no store is configured rather than silently pretending. Wired into `cmd/gateway`: set any of `NIA_RISK_FLAG_AT`, `NIA_RISK_REVOKE_AT`, or `NIA_RISK_KILL_AT` and every allowed call gets scored and observed, unset (the default) skips monitoring entirely, same additive posture as the tool catalog check. `cmd/gateway` doesn't have a credential store wired into it, so a revoke threshold crossed there degrades to the audited no-op described above rather than a real revoke, that's the next gap, not a hidden one. Verified with `go test ./... -race`: seven tests on `HistoryScorer` including a concurrent-calls race check, ten on `Monitor` (flag, kill, revoke with a store, revoke without one, revoke touching only the calling agent's active credentials) plus four on `ThresholdsFromEnv`, and five more on the gateway's handler (monitoring skipped when unconfigured, a score below every threshold, crossing flag, crossing kill with a real `policy.Kill` call asserted), same build-verification path as everything else in this section.

## Layout

```
cmd/api        control-plane API: registration, inventory, credentials, grants, kill switch
cmd/gateway    Agent/MCP gateway: the hot path, resolve -> check -> forward
cmd/niactl     operator CLI, talks to cmd/api over HTTP
internal/      identity, registry, credentials, policy, audit, risk, monitoring, graph
deployments/   Dockerfiles, docker-compose, and the OpenFGA store/model bootstrap for local dev
docs/          architecture and data model
```

## Running locally

```bash
go build ./...
go vet ./...
go test ./...

# in one terminal
go run ./cmd/api

# in another
go run ./cmd/gateway

# register an agent
go run ./cmd/niactl register -ref agent:billing-reconciler -owner bogdan -purpose "reconciles invoices nightly"

# list what's registered
go run ./cmd/niactl list

# register a tool it's allowed to call
go run ./cmd/niactl tool register -name invoice-lookup -transport http -risk read_only -owner bogdan

# issue it a credential
go run ./cmd/niactl credential issue -ref agent:billing-reconciler -kind api_key -ttl 24h

# revoke one key without touching the agent itself
go run ./cmd/niactl credential revoke -id <credential_id> -reason "key leaked in a log"

# pull the kill switch, the bigger hammer, for when the agent itself is compromised
go run ./cmd/niactl kill -ref agent:billing-reconciler -incident INC-001

# review what happened to it
go run ./cmd/niactl audit -ref agent:billing-reconciler
```

The commands above run against the in-memory policy client, no Tessera, OpenFGA, or Postgres required. To point `cmd/api` and `cmd/gateway` at a real Tessera instance instead, set three environment variables before starting them: `NIA_TESSERA_BASE_URL` (Tessera.Service's URL), `NIA_TESSERA_JWT_SIGNING_KEY` (base64, the exact same value Tessera.Service was started with as `TESSERA_JWT_SIGNING_KEY`), and, only if Tessera isn't running with its own defaults, `NIA_TESSERA_JWT_ISSUER` / `NIA_TESSERA_JWT_AUDIENCE`. See `internal/policy/from_env.go` for the full list and defaults.

`deployments/docker-compose.yml` brings up the full stack, NIA's two services plus Tessera, OpenFGA, and Postgres, see the Status section above for what's actually been confirmed. OpenFGA needs a store and an authorization model before Tessera can use it, which can't be baked into compose (a store only gets an id once OpenFGA is already running): bring up `postgres` and `openfga` first, run `deployments/bootstrap-openfga.sh`, add the store id it prints to `.env` as `TESSERA_OPENFGA_STORE_ID`, then bring up the rest. The stack's `postgres` service also now backs the audit trail (`NIA_AUDIT_DATABASE_URL`, hardcoded in `docker-compose.yml`, it isn't a secret), no extra setup needed for that part, just `go mod tidy` first if this is the first build since `internal/audit/postgres_sink.go` was added, it pulls in `lib/pq`.

## License

[MIT](LICENSE).
