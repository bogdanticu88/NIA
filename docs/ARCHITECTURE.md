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
| Audit trail | `internal/audit` | Append-only sink, aggregates gateway decisions, registry changes, and Tessera's own `AuditEvent`s into one stream |
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

Tessera today is a .NET library plus reference in-memory implementations. Its own roadmap already lists what NIA needs from it: a minimal HTTP surface for kill, restore, and onboard (v1.2, not yet built), and an OpenFGA SDK adapter with paging and chunking (v1.1, not yet built). Rather than reimplementing Tessera's invariants in Go, the plan is to finish that roadmap as part of standing NIA up, since NIA is the first real consumer of exactly that surface:

1. Build the OpenFGA SDK adapter for `IAuthorizationStore` in Tessera (v1.1 item). This is what makes Tessera talk to a real OpenFGA instance instead of the in-memory reference store.
2. Build the minimal HTTP surface (kill, restore, onboard) in Tessera (v1.2 item), with issuer/audience validation. This turns Tessera from a library you embed into a service NIA can call over HTTP.
3. `internal/policy` in NIA becomes a thin REST client against that surface: register calls onboard, kill switch calls kill, credential/permission changes call whatever the reconcile endpoint ends up being.
4. The gateway keeps calling OpenFGA directly for the actual per-request check, same as Tessera's own architecture, so authorization stays off the hot path.

Until step 2 lands, there's no way for Go code to call into Tessera's C# types directly, so the honest short-term state is: `internal/policy` defines a Go-side interface shaped like Tessera's (`WriteGrants`, `Kill`, `Restore`, `Check`), backed by an in-memory implementation for local dev, ready to be pointed at Tessera's HTTP surface the moment it exists. Calling this out explicitly in the repo so it doesn't get mistaken for a finished integration.

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

This is the architecture and the repo skeleton: package boundaries, the interfaces each package exposes, and enough scaffolding that `go build` and `go vet` pass clean. It is not a working implementation of all seventeen items. Agent identity, the policy client interface, and the kill switch bridge are the pieces worth building out first, since they're what makes the Tessera integration real instead of aspirational. Tool registration, risk scoring, and the identity graph are the pieces that most benefit from real usage data before locking in a schema, so they're stubbed thin on purpose.
