# NIA: Non-Human Identity & Agent Security

## An Agent Security Control Plane

### The problem

An AI agent isn't just software anymore. It holds credentials, gets granted permissions, calls tools, reaches into data it was never explicitly handed, and takes actions on its own initiative, sometimes on behalf of a human, sometimes on behalf of another agent. Once you have more than a couple of these running, three questions stop having obvious answers: what is this agent actually allowed to do, who authorised it to do that, and if it starts doing something it shouldn't, how do you stop it in the next second instead of the next deploy.

NIA treats every agent, service account, and automated identity as a first-class non-human identity (NHI) with its own registration, its own credentials, its own permission graph, and its own kill switch. It's modelled on how you'd run IAM for humans, because underneath it's the same problem: know who's asking, decide if they're allowed, watch what they do, and be able to cut them off immediately when something's wrong.

### Why this isn't a green-field design

Most of the hard part of this already exists and works: Tessera. It's the relationship-based authorization control plane I built on OpenFGA, doing live per-request authorization checks and a surgical kill switch, delete a tuple, the next check denies, no token revocation, no redeploy. That's the Policy Engine, Authorization, Credential Revocation, and Kill Switch boxes in the brief, already solved. NIA doesn't reinvent that layer, it generalizes it: Tessera's `client_ref` becomes NIA's agent identity, Tessera's `Grant` becomes NIA's permission, and Tessera's design invariants (sentinel-first kill, idempotent reconcile, one canonical form, per-client mutual exclusion) carry over unchanged. What NIA adds is everything Tessera was never scoped to do: agent registration and lifecycle, tool and MCP awareness, credential issuance (not just identity resolution), risk scoring, runtime behavioral monitoring, agent-to-agent trust, delegation, and an identity graph tying humans, agents, tools, and data together.

* * *

### The two planes

Same split Tessera already uses, carried up a level.

```
                                   HUMAN
                                     │
                                     ▼
                    ┌────────────────────────────────┐
                    │        NIA CONTROL PLANE        │   Go, this repo
                    │  registration, identity,        │
                    │  credentials, tool registry,    │
                    │  risk scoring, audit,           │
                    │  identity graph, delegation      │
                    └────────────────┬─────────────────┘
                                     │ declares grants, issues creds,
                                     │ manages the identity graph
                                     ▼
                    ┌────────────────────────────────┐
                    │            TESSERA               │   .NET, existing repo
                    │  reconciles grants -> OpenFGA    │
                    │  tuples, kill switch, sentinel   │
                    └────────────────┬─────────────────┘
                                     │ writes/deletes tuples
                                     ▼
                              ┌─────────────┐
                              │   OpenFGA   │   relationship checks
                              └──────┬──────┘
                                     │ allow / deny, live, every request
                                     ▼
        ┌───────────────────────────────────────────────────┐
        │              AGENT / MCP GATEWAY (hot path)         │   Go, this repo
        │   resolves agent identity, checks OpenFGA,          │
        │   forwards or blocks, streams to monitoring         │
        └───────────┬────────────────────────┬────────────────┘
                    │                        │
               ┌────▼────┐              ┌────▼────┐
               │  Tools  │              │  Data   │
               └─────────┘              └─────────┘
                                     │
                                     ▼
                    ┌────────────────────────────────┐
                    │            MONITORING            │
                    │   risk scoring, anomaly detect   │
                    └────────────────┬─────────────────┘
                                     │
                          ┌──────────▼──────────┐
                          │   Detect / Block     │
                          └──────────┬───────────┘
                                     │
                          ┌──────────▼──────────┐
                          │   Revoke / Kill      │───▶ back to Tessera
                          └──────────────────────┘
```

The rule that makes Tessera work applies here too: the control plane never sits on the hot path. The gateway checks OpenFGA directly on every request. NIA's control plane and Tessera only manage the state those checks read, who exists, what they're allowed, and whether they've been killed. That's what makes the kill switch instant. It's a state change, not a code path change.

* * *

### The seventeen MVP items, mapped to modules

The brief lists seventeen things to build. None of them are new categories, they're all one of: identity, policy, enforcement, or observability. Here's where each one lives.

| MVP item | Module | Notes |
|---|---|---|
| Agent registration | `internal/registry` | Onboards a new `AgentRef`, mirrors Tessera's `ClientProvisioner` |
| NHI inventory | `internal/registry` + `internal/store` | Queryable list/search over all registered identities |
| Agent identity | `internal/identity` | Canonical `AgentRef`, assurance level, lifecycle state (active/suspended/killed) |
| Credentials | `internal/credentials` | Issuance, rotation, binding of API keys, short-lived tokens, mTLS certs to an `AgentRef`. Tessera assumes credentials already exist and only resolves them, NIA owns the credential lifecycle itself |
| Permissions | `internal/policy` | Thin Go client over Tessera's `Grant` model (api_group or endpoint-level grants), extended with tool and data scoped grants |
| Tool registration | `internal/registry/tools` (sub-package) | Catalog of callable tools, each with a risk classification |
| MCP integration | `cmd/gateway` | MCP-aware transport in the gateway, intercepts tool-call requests, resolves the calling agent, checks policy before invoking |
| Policy engine | **Tessera** (external) | Not rebuilt. NIA's `internal/policy` is a client for it |
| Authorization decisions | OpenFGA, via Tessera's `IAuthorizationStore.CheckAsync` | Live, per-request, no cache |
| Audit trail | `internal/audit` | Append-only sink. Gateway decisions and registry changes both write here now, one event shape either way; Tessera's own `AuditEvent`s still don't, no bridge exists yet. `PostgresSink` gives it a real, shared backend, confirmed against a live stack, `nia-api` and `nia-gateway` reading and writing the same table, see "What this scaffold is, and isn't" |
| Risk scoring | `internal/risk` | New. Scores agents and individual calls off signals: novel tool use, sensitive data touched, deviation from historical pattern. Natural fit for CENTIPEDE's anomaly detection work |
| Runtime monitoring | `internal/monitoring` | Consumes the gateway's request stream, feeds the risk engine, raises detect/block signals |
| Credential revocation | `internal/credentials` (revoke path) | Distinct from the kill switch: revokes one credential without killing the whole identity |
| Kill switch | Tessera's `KillSwitchService`, called from `internal/policy` | Reused as-is: sentinel-first delete, confirmed, one client, nothing else touched |
| Agent-to-agent trust | `internal/graph` | Trust edges between `AgentRef`s: which agents may invoke which other agents |
| Delegation | `internal/graph` + `internal/policy` | "Acting on behalf of" relations layered onto OpenFGA as a `delegate` relation alongside Tessera's existing `member` / method relations |
| Basic identity graph | `internal/graph` | The graph tying humans, agents, tools, and data together, the thing you query when you need blast-radius analysis after an incident |

* * *

### The identity graph

This is the part Tessera doesn't have, because Tessera only ever needed to know about one kind of node (a client) and one kind of edge (a grant). NIA needs more of both, because "what can this agent reach, transitively, through delegation and trust" is a graph question, not a lookup.

Nodes: `Human`, `Agent` (the NHI itself), `Tool`, `DataResource`, `Credential`.

Edges: `owns` (Human owns Agent), `delegates_to` (Agent delegates to Agent, time-bounded), `trusts` (Agent trusts Agent, for agent-to-agent calls), `member_of` (Agent member of a group, same shape as Tessera's `bu_group`), `grants` (Agent granted access to Tool or DataResource, same shape as Tessera's endpoint/api_group grants), `bound_to` (Credential bound to Agent).

This graph is queryable independently of the live OpenFGA checks. OpenFGA answers "can X do Y right now." The identity graph answers "everything X could reach, directly or transitively," which is what you actually want when doing incident response on a compromised agent, or when figuring out the blast radius before granting something new.

* * *

### Integration plan for Tessera

Tessera started as a .NET library plus reference in-memory implementations. Its own roadmap listed what NIA needed from it: a minimal HTTP surface for kill, restore, and onboard (v1.2), and an OpenFGA REST adapter with paging and chunking (v1.1). Rather than reimplementing Tessera's invariants in Go, the plan was to finish that roadmap as part of standing NIA up, since NIA is the first real consumer of exactly that surface. That plan is done:

1. Built the REST adapter for `IAuthorizationStore` in Tessera (v1.1), talking to OpenFGA's plain HTTP API rather than the official SDK. This is what lets Tessera talk to a real OpenFGA instance instead of the in-memory reference store.
2. Built the minimal HTTP surface in Tessera (v1.2): onboard, kill, restore, and a read (`GET /clients/{client_ref}`, added once NIA's own client needed a way to read current state before writing to it), all behind a hand-rolled HS256 bearer auth gate. This turned Tessera from a library you embed into a service NIA can call over HTTP.
3. `internal/policy/tessera_client.go` in NIA is that REST client: `TesseraHTTPClient` implements the same `Client` interface `InMemoryClient` does. WriteGrants and DeleteGrants do a read, merge, then a full onboard, since onboard is Tessera's only mutation route and it's full-state reconcile, not incremental. Kill calls kill. Restore calls restore.
4. The gateway still calls OpenFGA directly for the actual per-request check, same as Tessera's own architecture, so authorization stays off the hot path. `TesseraHTTPClient.Check` exists for the control plane's own use (inspection, niactl, that kind of call), not the gateway's hot path, and it reads Tessera's declared grant state, not live OpenFGA truth, see the type's own doc comment for why those two aren't always the same thing right after a kill and restore.

Both implementations of `Client` (`InMemoryClient`, `TesseraHTTPClient`) live in `internal/policy`, verified against each other's own test suite plus a cross-language smoke test (`internal/policy/tessera_client_live_test.go`) that spawns a real `Tessera.Service` process and drives it over actual HTTP, the same live-process pattern Tessera's own `tools/ServiceHarness` uses. That live test is what caught a real bug during this work: a client-side optimization that skipped re-declaring grants Tessera already had on file, which looked safe until the live test showed a kill followed by a restore leaves the declared grant list untouched while clearing the actual OpenFGA tuples, so skipping the redeclare silently left the agent unauthorized while every read-only call still reported it as granted. Fixed by always calling onboard on a `WriteGrants` call against a known agent, not just when the requested grants are new. Known gaps that remain, all documented in `TesseraHTTPClient`'s own comment rather than left implicit: the read-modify-write only serializes within one client instance, not across replicas (needs Tessera's own database advisory lock, still on its roadmap); most calls other than Kill authenticate as a configured system identity rather than a real per-operator one, since `Client.Restore` and the others carry no operator parameter to sign with; and `business_unit` can be preserved through this client but never set by it, nothing in `Client` carries it.

`cmd/api` and `cmd/gateway` pick which `Client` to run against at startup (`policy.FromEnv`, `internal/policy/from_env.go`), `NIA_TESSERA_BASE_URL` unset keeps the in-memory default, setting it and the shared signing key alongside it switches to `TesseraHTTPClient`. Wiring that in surfaced a second real bug, this one only visible with an actual `cmd/api` process talking to an actual `Tessera.Service` process, not from either side's own test suite: NIA's own agent ref convention is type-prefixed (`agent:billing-reconciler`, see `identity.AgentRef.Ref`), and Tessera's `CanonicalForm.ClientRef` rejects `:` outright, so every single call failed with "client_ref contains an invalid character" the moment a ref in NIA's actual shape crossed the wire, something no unit test caught because none of them used a colon-bearing ref. Fixed with a reversible, collision-free escape at the `TesseraHTTPClient` boundary (`encodeClientRef`/`decodeClientRef`), confirmed against the real service the same way the first bug was: a register, a kill, and a direct read of Tessera's own state afterward, over real HTTP, through `cmd/api`, not a mock.

`deployments/docker-compose.yml` wires all four services (`nia-api`, `nia-gateway`, `tessera`, `openfga`, plus `postgres`) together, with Dockerfiles for `cmd/api`, `cmd/gateway` (this repo), and `Tessera.Service` (the Tessera repo), and it has actually been run: all five containers built and came up healthy, and `deployments/bootstrap-openfga.sh` creates the OpenFGA store and authorization model Tessera needs to point at it, the manual step docker-compose can't do on its own since a store only gets an id once OpenFGA is already up. With that in place, a client was onboarded through Tessera's real HTTP surface, checked as allowed directly against OpenFGA, killed, and checked again as denied, real tuples written and deleted in a real OpenFGA store, not the in-memory one Tessera used in every check up to this point.

That run caught two more real bugs, both in Tessera's OpenFGA adapter, both only reachable by pointing it at a real store. `Program.cs` registered `IAuthorizationStore` with `AddHttpClient<IAuthorizationStore, OpenFgaAuthorizationStore>(...).AddTypedClient(factory)`, and `AddTypedClient`'s type parameter is inferred from the factory delegate's return type, not carried over from the call it's chained onto, so it silently bound the factory to the concrete `OpenFgaAuthorizationStore` type instead of the `IAuthorizationStore` interface everything else asks for. A request for `IAuthorizationStore` fell through to `AddHttpClient`'s own default factory, which tries to construct `OpenFgaAuthorizationStore` through the container and can't resolve its plain `string storeId` constructor argument, throwing the moment anything actually used the store. Fixed with an explicit `AddTypedClient<IAuthorizationStore>(...)`. Second, `OpenFgaAuthorizationStore.ReadTuplesForClientAsync`, which both `ClientProvisioner`'s reconcile diff and `KillSwitchService`'s read-delete loop depend on, filtered OpenFGA's `/read` endpoint by `user` alone. Real OpenFGA rejects that outright, "the object type field is required", it has no query shape for "everything this user touches regardless of type", only the in-memory store tolerated that. Fixed by reading each of the two object types Tessera ever writes against, `api_group` and `api_endpoint`, one at a time with the type-only object filter, and merging the results. Neither bug was reachable by the harness tests or by the earlier live test against Tessera's in-memory store, both are in Tessera's own history on `feature/openfga-http-adapter`, right after the Dockerfile commit.

* * *

### Repo layout

```
nia/
├── cmd/
│   ├── api/          entry point for the control-plane API (registration, inventory, credentials, tools, audit, risk, graph)
│   ├── gateway/       entry point for the Agent/MCP gateway (hot path)
│   └── niactl/        CLI for operators: register, grant, kill, restore, inspect
├── internal/
│   ├── identity/      AgentRef, assurance levels, lifecycle state
│   ├── registry/       agent + tool registration, NHI inventory
│   ├── credentials/    credential issuance, rotation, revocation
│   ├── policy/         client for Tessera / OpenFGA (permissions, authorization, kill switch)
│   ├── audit/          append-only audit sink and aggregation
│   ├── risk/            risk scoring
│   ├── monitoring/     runtime monitoring, detect/block
│   ├── graph/           identity graph, trust, delegation
│   ├── store/           persistence interfaces (Postgres + in-memory reference, same choice Tessera makes)
│   └── transport/http/  shared HTTP transport helpers
├── deployments/
│   └── docker-compose.yml   nia-api, nia-gateway, tessera, openfga, postgres
└── docs/
    ├── ARCHITECTURE.md   this file
    └── DATA_MODEL.md     identity graph schema in detail
```

Every `internal/*` package that stands in for a not-yet-implemented piece of Tessera ships with an in-memory reference implementation, same choice Tessera itself made, so the whole thing runs locally without external dependencies while the real adapters get built.

* * *

### What this scaffold is, and isn't

This started as architecture and a repo skeleton: package boundaries, the interfaces each package exposes, and enough scaffolding that `go build` and `go vet` pass clean, with in-memory reference implementations standing in for everything. It is still not a working implementation of all seventeen items, but four pieces have moved past that: the policy client (see "Integration plan for Tessera" above, both against Tessera's in-memory store and a real Tessera-plus-OpenFGA-plus-Postgres stack), the kill switch bridge (the same integration, `Kill` deletes real tuples), the audit trail's write path (the gateway writes every decision, allow, deny, check error, to `internal/audit`, not just `cmd/api`'s own registration and kill events, and both are queryable over HTTP and through `niactl audit`), and the audit trail's storage: `internal/audit.PostgresSink` is a second `Store` implementation, `database/sql` plus `lib/pq`, that `audit.FromEnv` picks when `NIA_AUDIT_DATABASE_URL` is set, and `docker-compose.yml` points both NIA services at the stack's own `postgres` service. Confirmed against a real stack, not just unit tests: registered an agent through `nia-api`, denied a gateway call against it, killed it, then read `nia-api`'s own `GET /agents/{ref}/audit` back and got all three events in order, `nia-api` and `nia-gateway` reading and writing the same table, which is the entire reason this piece exists, see README.md's Status section for the full sequence. Tool registration, risk scoring, and the identity graph are the pieces that most benefit from real usage data before locking in a schema, so they're still stubbed thin on purpose.
