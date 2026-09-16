# NIA: Non-Human Identity & Agent Security

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

# pull the kill switch
go run ./cmd/niactl kill -ref agent:billing-reconciler -incident INC-001
```

The commands above run against the in-memory policy client, no Tessera, OpenFGA, or Postgres required. To point `cmd/api` and `cmd/gateway` at a real Tessera instance instead, set three environment variables before starting them: `NIA_TESSERA_BASE_URL` (Tessera.Service's URL), `NIA_TESSERA_JWT_SIGNING_KEY` (base64, the exact same value Tessera.Service was started with as `TESSERA_JWT_SIGNING_KEY`), and, only if Tessera isn't running with its own defaults, `NIA_TESSERA_JWT_ISSUER` / `NIA_TESSERA_JWT_AUDIENCE`. See `internal/policy/from_env.go` for the full list and defaults.

`deployments/docker-compose.yml` brings up the full stack, NIA's two services plus Tessera, OpenFGA, and Postgres, see the Status section above for what's actually been confirmed. OpenFGA needs a store and an authorization model before Tessera can use it, which can't be baked into compose (a store only gets an id once OpenFGA is already running): bring up `postgres` and `openfga` first, run `deployments/bootstrap-openfga.sh`, add the store id it prints to `.env` as `TESSERA_OPENFGA_STORE_ID`, then bring up the rest.

## License

MIT.
