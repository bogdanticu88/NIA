# NIA: Non-Human Identity & Agent Security

An agent security control plane: know what an agent is allowed to do, who authorised it, what it actually did, and how to stop it, in the next second instead of the next deploy.

NIA generalizes [Tessera](https://github.com/bogdanticu88/tessera), a relationship-based authorization control plane built on [OpenFGA](https://openfga.dev), from "M2M API client" to "AI agent." Tessera's live per-request checks and surgical kill switch aren't rebuilt here, they're reused as the policy engine layer. NIA adds agent registration, credential lifecycle, tool and MCP awareness, risk scoring, runtime monitoring, agent-to-agent trust, delegation, and an identity graph on top.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full design and the seventeen-item MVP-to-module map, and [`docs/DATA_MODEL.md`](docs/DATA_MODEL.md) for the identity graph schema.

## Status

Package boundaries, interfaces, and in-memory reference implementations exist for every one of the seventeen MVP components. `internal/policy` additionally has a second, real implementation, `TesseraHTTPClient`, that drives an actual Tessera.Service instance over HTTP instead of the in-memory reference. `cmd/api` and `cmd/gateway` pick between the two at startup based on environment (`policy.FromEnv`, unset `NIA_TESSERA_BASE_URL` means the in-memory one, same "runs out of the box" default as before).

What's actually been verified, and how:

- `internal/policy`: unit tests against a fake HTTP server (network failures, malformed and oversized responses, cancellation, concurrent writers) plus a live test that spawns a real `Tessera.Service` process and drives it over actual HTTP (`internal/policy/tessera_client_live_test.go`, opt-in via `NIA_TESSERA_REPO_PATH`, a checked-out Tessera repo with `src/Tessera.Service` already built).
- `cmd/api` and `cmd/gateway` against that same real `Tessera.Service` process, driven over real HTTP end to end, not just through Go's own test harness: registered an agent, killed it through `POST /policy/kill`, and confirmed Tessera's own state showed the kill. This is what caught a real bug (an agent ref containing `:`, NIA's own convention, `agent:billing-reconciler`, fails Tessera's `client_ref` validation outright) that no unit test had a reason to exercise, since none of them used a ref in that shape. Fixed with a reversible encoding at the `TesseraHTTPClient` boundary, see its doc comment, point 5.

What has not: the full `docker-compose.yml` stack, four services actually talking to each other under Docker (`nia-api`, `nia-gateway`, `tessera`, `openfga`, plus `postgres`), and Tessera against real OpenFGA rather than its in-memory store. This sandbox has no Docker daemon, so none of that has been run here, `deployments/Dockerfile.api`, `Dockerfile.gateway`, and Tessera's own `Dockerfile` are written but not `docker build`-verified, and `openfga`'s store/model still need creating by hand against its API before Tessera can point at it (see the comment at the top of `docker-compose.yml`). Confirm this on a machine with Docker before relying on it.

## Layout

```
cmd/api        control-plane API: registration, inventory, credentials, grants, kill switch
cmd/gateway    Agent/MCP gateway: the hot path, resolve -> check -> forward
cmd/niactl     operator CLI, talks to cmd/api over HTTP
internal/      identity, registry, credentials, policy, audit, risk, monitoring, graph
deployments/   Dockerfiles and docker-compose for local dev (nia-api, nia-gateway, tessera, openfga, postgres)
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

`deployments/docker-compose.yml` brings up the full stack, NIA's two services plus Tessera, OpenFGA, and Postgres, see the Status section above for what's actually been confirmed to work versus what still needs a Docker-equipped machine to verify.

## License

MIT.
