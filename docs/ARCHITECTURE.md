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
| NHI inventory | `internal/registry` | `GET /agents` and `niactl list` return every registered `AgentRef`. This is a full, unfiltered dump of `InMemoryAgentRegistry`'s map today, not a queryable search index, filtering or paging over a large fleet would need real storage behind it, which is why `internal/store` isn't listed here, that package doesn't exist yet, add it once a real filter need shows up rather than building it speculatively |
| Agent identity | `internal/identity` | Canonical `AgentRef`, assurance level, lifecycle state (active/suspended/killed) |
| Credentials | `internal/credentials` | Issuance, rotation, binding of API keys, short-lived tokens, mTLS certs to an `AgentRef`. Tessera assumes credentials already exist and only resolves them, NIA owns the credential lifecycle itself. Wired into `cmd/api` (`POST /agents/{ref}/credentials`, `GET` to list) and `niactl credential issue` / `list`, verified with `go test ./... -race` |
| Permissions | `internal/policy` | Thin Go client over Tessera's `Grant` model (api_group or endpoint-level grants), extended with tool and data scoped grants. `WriteGrants`/`DeleteGrants`/`ListGrants` have always existed on the client itself; they only reached `cmd/api` (`POST`/`DELETE`/`GET /agents/{ref}/grants`) and `niactl grant write` / `delete` / `list` in this pass, before that there was no way to actually grant an agent a permission through the control-plane API at all, verified with `go test ./... -race` |
| Tool registration | `internal/registry/tools` (sub-package) | Catalog of callable tools, each with a risk classification. Wired into `cmd/api` (`POST /tools`, `GET /tools`, `GET /tools/{name}`) and `niactl tool register` / `list` / `get`, verified with `go test ./... -race`. The gateway consults this catalog now too, see the MCP integration row below |
| MCP integration | `cmd/gateway` | MCP-aware transport in the gateway, intercepts tool-call requests, resolves the calling agent, checks policy before invoking. When `NIA_TOOLS_API_URL` is set, a step is inserted in front: look the tool up in `cmd/api`'s catalog over HTTP, reject with 404 before ever reaching the policy check if nobody registered it. When `NIA_GATEWAY_RESOURCE_RULES_PATH` is also set, a second step follows the tool-level check: the call's arguments are turned into resource object names and any classified `sensitive` or above needs its own `data` grant, see "Resource sensitivity" below. Both unset, behavior is unchanged, additive rather than a stricter default nothing opted into. See `tools.HTTPReader`, `tools.FromEnvReader`, and `cmd/gateway/resources.go` |
| Policy engine | **Tessera** (external) | Not rebuilt. NIA's `internal/policy` is a client for it |
| Authorization decisions | OpenFGA, via Tessera's `IAuthorizationStore.CheckAsync` | Live, per-request, no cache |
| Audit trail | `internal/audit` | Append-only sink. Gateway decisions and registry changes both write here now, one event shape either way; Tessera's own `AuditEvent`s still don't, no bridge exists yet. `PostgresSink` gives it a real, shared backend, confirmed against a live stack, `nia-api` and `nia-gateway` reading and writing the same table, see "What this scaffold is, and isn't" |
| Risk scoring | `internal/risk` | New. Scores agents and individual calls off signals: novel tool use, sensitive data touched, deviation from historical pattern. `HistoryScorer` is the first real `Scorer`, three signals now, novel-tool detection, a risk-class-weighted signal off the tool catalog, and a sensitive-resource signal off `internal/sensitivity` when a call's arguments touched anything classified `sensitive` or above. Not CENTIPEDE's anomaly detection yet, that's still the intended eventual replacement, and `volume_deviation` still needs rate tracking this scaffold doesn't have. Verified with `go test ./... -race` |
| Runtime monitoring | `internal/monitoring` | Consumes the gateway's request stream, feeds the risk engine, raises detect/block signals. Wired into `cmd/gateway`: every allowed call is scored and observed when `NIA_RISK_FLAG_AT` / `NIA_RISK_REVOKE_AT` / `NIA_RISK_KILL_AT` is set, unset means monitoring is skipped entirely. Thresholds compare against a running per-agent total now, not a single call's score in isolation, `Monitor.Observe` accumulates every scored call into `cumulative[agentRef]` and only resets it on a kill, a flag or a revoke leaves the total in place, see `Monitor`'s own doc comment for why a kill is the one action that justifies starting over. `ActionRevoke` actually revokes, every active credential for the agent via `internal/credentials.Store`, though `cmd/gateway` itself has no credential store wired in yet, so a revoke threshold crossed there degrades to an audited no-op. The gateway's own tool-call response now carries a `risk` block, this call's value and signals plus the agent's current cumulative total and whatever action fired, when monitoring is configured, so a caller doesn't have to separately query for what just happened. Verified with `go test ./... -race`, including a concurrency test that fires fifty simultaneous calls for one agent and checks the total lost no updates |
| Credential revocation | `internal/credentials` (revoke path) | Distinct from the kill switch: revokes one credential without killing the whole identity. `POST /credentials/{id}/revoke` and `niactl credential revoke`, writes `credential.revoked` to the audit trail same as every other control-plane action, verified with `go test ./... -race` |
| Kill switch | Tessera's `KillSwitchService`, called from `internal/policy` | Reused as-is: sentinel-first delete, confirmed, one client, nothing else touched |
| Agent-to-agent trust | `internal/graph` | `trusts` edges between `AgentRef`s, recorded and queried through `POST /graph/edges` and `niactl graph add-edge`. This is bookkeeping the graph can answer questions about, not yet something the gateway's live authorization check consults, see the Delegation row below for the same gap |
| Delegation | `internal/graph` + `internal/policy` | `delegates_to` edges are recorded and queryable the same way `trusts` is, wired into `cmd/api` and `niactl`, verified with `go test ./... -race`. Layering `delegate` onto OpenFGA as a relation Tessera's own checks understand, so a delegation edge actually changes what the gateway allows rather than only what the graph reports after the fact, is still open, `internal/policy` doesn't consult `internal/graph` today |
| Basic identity graph | `internal/graph` | The graph tying humans, agents, tools, and data together, the thing you query when you need blast-radius analysis after an incident. Wired into `cmd/api` (`POST /graph/nodes`, `POST /graph/edges`, `GET /graph/{id}/neighbors?kind=`, `GET /graph/{id}/reachable?kinds=`) and `niactl graph add-node` / `add-edge` / `neighbors` / `reachable`, verified with `go test ./... -race`. `reachable` defaults to every edge kind when `-kinds` is omitted, the blast-radius question usually means "everything, however it's reachable," not one relation at a time |

* * *

### The identity graph

This is the part Tessera doesn't have, because Tessera only ever needed to know about one kind of node (a client) and one kind of edge (a grant). NIA needs more of both, because "what can this agent reach, transitively, through delegation and trust" is a graph question, not a lookup.

Nodes: `Human`, `Agent` (the NHI itself), `Tool`, `DataResource`, `Credential`.

Edges: `owns` (Human owns Agent), `delegates_to` (Agent delegates to Agent, time-bounded), `trusts` (Agent trusts Agent, for agent-to-agent calls), `member_of` (Agent member of a group, same shape as Tessera's `bu_group`), `grants` (Agent granted access to Tool or DataResource, same shape as Tessera's endpoint/api_group grants), `bound_to` (Credential bound to Agent).

This graph is queryable independently of the live OpenFGA checks. OpenFGA answers "can X do Y right now." The identity graph answers "everything X could reach, directly or transitively," which is what you actually want when doing incident response on a compromised agent, or when figuring out the blast radius before granting something new.

* * *

### Resource sensitivity

`internal/sensitivity` answers a narrower question than the identity graph: given a resource name, a tool argument, a column, a field, a data object, how sensitive is it. Five levels, `public`, `internal`, `confidential`, `sensitive`, `critical`, `public` being the zero value and the default for anything nobody declared a rule for. This is deliberately a flat rule list, not inference: an operator writes "customer.ssn is critical," the classifier looks it up, first matching rule wins. That's what makes it explainable, an incident review can point at the exact rule that made a call get flagged, not a model's guess.

The point of this package is to name resources the same way `policy.GrantForData` already does, `GrantForData("customer.ssn")` is an authorization grant naming that resource, a `sensitivity.Rule{Pattern: "customer.ssn", Level: sensitivity.Critical}` is a classification of the same name. The two are meant to be read together: an agent can be granted `database.query` as a tool while still lacking the data grant for `customer.ssn`, which is what makes "authorized to call the tool, not authorized to touch this column" enforceable without inventing a second authorization system, `internal/policy`'s existing `data` grant kind already covers it, see "The seventeen MVP items" table above.

Wired in now: `POST /tools/{tool}/call` decodes an optional `arguments` object from the request body (see `cmd/gateway`'s `toolCallRequest`), an `ArgumentResourcePolicy` (`cmd/gateway/resources.go`, `NIA_GATEWAY_RESOURCE_RULES_PATH`) turns those arguments into the resource object names they touch, and any resource classified at `sensitive` or above needs its own `policy.GrantForData` grant, checked and audited the same way the tool-level grant is, `gateway.denied` with the specific resource named in the detail if it's missing. `internal/risk.HistoryScorer` also takes a `sensitivity.Classifier` now and adds a `sensitive_resource` signal, weighted higher again when the level is `critical`, when a scored call's `CallContext.Resources` includes anything at or above that threshold. All three env vars, `NIA_GATEWAY_RESOURCE_RULES_PATH`, `NIA_SENSITIVITY_RULES_PATH`, and the risk/monitoring thresholds, are independently optional, unset means the step it gates doesn't run, same additive posture as the tool catalog check before it.

* * *

### Attack simulation

`niactl simulate attack -scenario agent-hijack` is a deterministic, scripted scenario runner (`cmd/niactl/simulate.go`), not printed output standing in for one. It registers a real agent and a real tool catalog through `cmd/api`, writes real starting grants, then drives a sequence of real `POST /tools/{tool}/call` requests through `cmd/gateway`, the same request an MCP-aware caller would send, and prints what actually came back.

The one scenario today, `agent-hijack`, models an invoice-processing agent that's authorized (coarsely, at the tool level) for more than its normal work ever uses, a realistic over-privileged setup: broad RBAC says yes, behavioral signals are what actually catch the escalation. It's granted all seven tools up front, but `customers.ssn` is deliberately left ungranted at the data level, so its own step, a `database.query` call naming that column, gets a real, separate 403 from the gateway's argument inspection (see "Resource sensitivity" above), not just a risk flag, proving the Agent+Tool+Resource decision actually enforces something, not only the Agent+Tool one. The later steps escalate through tools the agent is authorized for but has never used, `customer.export`, `credential.read`, `external.upload`, exactly what `HistoryScorer`'s `novel_tool` and risk-class signals exist to catch: authorized, allowed, and still worth flagging.

Whether containment actually fired is read off the transcript itself, not asserted separately: the scenario's last step re-calls a tool the agent was granted and had already used successfully earlier in the same run, and if monitoring was configured with low enough thresholds to have killed the agent by then, that same call now comes back 403, `policy.Check` denying it because the kill sentinel is now in effect, not because anything about the request changed. That's an actual state transition, not a printed result, the same kill path `niactl kill` drives by hand.

Monitoring is opt-in the same way everywhere else in this codebase is: run the scenario against a gateway started without `NIA_RISK_FLAG_AT` / `NIA_RISK_REVOKE_AT` / `NIA_RISK_KILL_AT` set and every step comes back allowed, no risk block, no containment, that's an honest result too, it says the demo needs monitoring turned on, not that the pipeline is broken. `cmd/niactl/simulate.go`'s own tests (`cmd/niactl/simulate_test.go`) exercise the scenario's own well-formedness (every tool a step or grant names is actually registered) and drive `runScenario` against fake `cmd/api` and `cmd/gateway` HTTP servers standing in for the real processes, asserting on the actual call sequence and the containment-detection logic, not just describing it.

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
│   ├── sensitivity/     resource sensitivity classification (public/internal/confidential/sensitive/critical)
│   ├── monitoring/     runtime monitoring, detect/block
│   ├── graph/           identity graph, trust, delegation
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

This started as architecture and a repo skeleton: package boundaries, the interfaces each package exposes, and enough scaffolding that `go build` and `go vet` pass clean, with in-memory reference implementations standing in for everything. It is still not a working implementation of all seventeen items, but four pieces have moved past that: the policy client (see "Integration plan for Tessera" above, both against Tessera's in-memory store and a real Tessera-plus-OpenFGA-plus-Postgres stack), the kill switch bridge (the same integration, `Kill` deletes real tuples), the audit trail's write path (the gateway writes every decision, allow, deny, check error, to `internal/audit`, not just `cmd/api`'s own registration and kill events, and both are queryable over HTTP and through `niactl audit`), and the audit trail's storage: `internal/audit.PostgresSink` is a second `Store` implementation, `database/sql` plus `lib/pq`, that `audit.FromEnv` picks when `NIA_AUDIT_DATABASE_URL` is set, and `docker-compose.yml` points both NIA services at the stack's own `postgres` service. Confirmed against a real stack, not just unit tests: registered an agent through `nia-api`, denied a gateway call against it, killed it, then read `nia-api`'s own `GET /agents/{ref}/audit` back and got all three events in order, `nia-api` and `nia-gateway` reading and writing the same table, which is the entire reason this piece exists, see README.md's Status section for the full sequence. Credential issuance and revocation (`internal/credentials`) and tool registration (`internal/registry/tools`) are wired the same way now, real endpoints and `niactl` commands, real tests, not just an interface and an in-memory struct nothing else calls. The gateway also now checks a tool against that catalog before ever reaching the policy check, when `NIA_TOOLS_API_URL` is set, see the MCP integration row above for why that lookup goes over HTTP back to `cmd/api` rather than a second shared store. Risk scoring and runtime monitoring moved past their own stubs too: `HistoryScorer` produces a real, if simple, score off novel-tool, tool-risk-class, and now sensitive-resource signals, and `internal/monitoring.Monitor` acts on it, flag, revoke, or kill, all the way through to `internal/policy.Kill` for the kill case. The identity graph is wired the same way now too, `POST /graph/nodes` and `/graph/edges` plus the neighbors and reachable queries, and `niactl graph`, but it's still bookkeeping the graph itself answers questions about, not something `internal/policy` or the gateway's live check consults yet, a `trusts` or `delegates_to` edge doesn't change what OpenFGA allows, see the Agent-to-agent trust and Delegation rows above. The gateway's argument inspection closes a related but different gap: an agent authorized to call a tool can now still be denied a specific resource that call's arguments touch, when that resource is classified sensitive and the agent lacks the matching `data` grant, see "Resource sensitivity" above, this is enforcement, not just bookkeeping, `policy.Check` is genuinely consulted a second time with a `GrantForData` grant. Risk scoring moved from judging each call in isolation to a running per-agent total that a kill resets and nothing else does, see the Runtime monitoring row above, and the gateway's response now surfaces that total and whatever action it triggered rather than the caller having to separately ask. Permissions had a real gap closed too: `internal/policy.Client.WriteGrants`/`DeleteGrants`/`ListGrants` existed from early on but were never reachable over HTTP, so there was no way to actually grant an agent anything through the running system, `cmd/api`'s new grants endpoints and `niactl grant` close that. `niactl simulate attack` is the first thing in this repo that exercises the whole loop end to end through real processes, agent registration, grants, gateway calls, risk accumulation, and (when monitoring is configured) an actual kill and the subsequent real denial, see "Attack simulation" above; it is a CLI-driven test harness for the live system, not a second implementation of any of it. CENTIPEDE's actual anomaly detection replacing `HistoryScorer` is still just an intent, not code.
