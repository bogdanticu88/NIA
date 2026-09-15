# NIA: Non-Human Identity & Agent Security

An agent security control plane: know what an agent is allowed to do, who authorised it, what it actually did, and how to stop it, in the next second instead of the next deploy.

NIA generalizes [Tessera](https://github.com/bogdanticu88/tessera), a relationship-based authorization control plane built on [OpenFGA](https://openfga.dev), from "M2M API client" to "AI agent." Tessera's live per-request checks and surgical kill switch aren't rebuilt here, they're reused as the policy engine layer. NIA adds agent registration, credential lifecycle, tool and MCP awareness, risk scoring, runtime monitoring, agent-to-agent trust, delegation, and an identity graph on top.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full design and the seventeen-item MVP-to-module map, and [`docs/DATA_MODEL.md`](docs/DATA_MODEL.md) for the identity graph schema.

## Status

This is the architecture and repo scaffold: package boundaries, interfaces, and in-memory reference implementations for every component, same "runs out of the box, swap in the real thing later" pattern Tessera itself uses. It is not yet a working integration with Tessera or OpenFGA, see the integration plan in `docs/ARCHITECTURE.md` for what that requires and in what order.

## Layout

```
cmd/api        control-plane API: registration, inventory, credentials, grants, kill switch
cmd/gateway    Agent/MCP gateway: the hot path, resolve -> check -> forward
cmd/niactl     operator CLI, talks to cmd/api over HTTP
internal/      identity, registry, credentials, policy, audit, risk, monitoring, graph
deployments/   docker-compose for local dev (nia-api, nia-gateway, openfga, postgres)
docs/          architecture and data model
```

## Running locally

```bash
go build ./...
go vet ./...

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

Everything above runs against in-memory reference implementations, no Postgres, OpenFGA, or Tessera required. `deployments/docker-compose.yml` brings up Postgres and OpenFGA for when the real adapters land.

## License

MIT.
