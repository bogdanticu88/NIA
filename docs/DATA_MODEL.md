# NIA data model: the identity graph

This is the detail behind the identity graph section of `ARCHITECTURE.md`. It covers the node and edge types NIA tracks, and how they relate to the two other places identity-shaped data lives in this system: the agent registry (`internal/registry`) and the policy engine's tuple store (Tessera, via `internal/policy`).

## Why there are three places identity data lives, not one

It's worth being explicit about this, because it looks like duplication and isn't. Each of the three answers a different question, at a different speed, and none of them can answer the other two well:

The agent registry answers "does this identity exist, and what's its current lifecycle state." It's a simple keyed lookup, and it's what `cmd/api` and `cmd/gateway` both consult first.

OpenFGA, through Tessera, answers "can this identity do this specific thing, right now." It's a live, per-request check with no cache, because that's what makes the kill switch instant.

The identity graph answers "everything this identity could reach, directly or transitively." It's a traversal, not a lookup or a point check, and it's slower and heavier than either of the other two on purpose, because it's not on the hot path. You query it during onboarding review, permission design, and incident response, not on every tool call.

## Nodes

| Kind | Represents | Example |
|---|---|---|
| `Human` | A person accountable for one or more agents | `human:bogdan` |
| `Agent` | A non-human identity: an agent, service account, or automated process | `agent:billing-reconciler` |
| `Tool` | Something an agent can call | `tool:invoice-api` |
| `Data` | A data resource an agent can reach, directly or through a tool | `data:customer-pii` |

`Agent` nodes here are the same canonical ref as `identity.AgentRef` in the registry; the graph doesn't mint its own identity namespace, it references the registry's.

## Edges

| Kind | From → To | Meaning |
|---|---|---|
| `owns` | Human → Agent | Who's accountable if this agent misbehaves |
| `delegates_to` | Agent → Agent | Agent A can act on Agent B's behalf, time-bounded |
| `trusts` | Agent → Agent | Agent A accepts calls originating from Agent B |
| `member_of` | Agent → group | Same shape as Tessera's `bu_group` membership |
| `grants` | Agent → Tool \| Data | Mirrors a live grant in the policy engine |
| `bound_to` | Credential → Agent | Which agent a credential belongs to |

`grants` edges are intentionally redundant with what Tessera/OpenFGA already knows. They're written to the graph at the same time they're written to the policy client (both calls happen from `internal/policy`'s caller, typically `cmd/api`'s grant handler), so the graph has a complete picture for traversal without querying OpenFGA node-by-node, which OpenFGA's tuple model isn't built for efficiently at graph scale.

## The query that matters most: blast radius

Given a compromised or suspect agent, `Graph.Reachable` answers: starting from this agent, and following `delegates_to`, `trusts`, and `grants` edges transitively, what else is reachable. That set is your blast radius, and it's the thing you want on screen in the first sixty seconds of an incident, before you decide whether a `Kill` (via `internal/policy`) needs to cascade to more than one agent.

This is also why `delegates_to` is modeled as its own edge kind rather than folded into `grants`: a delegation chain (agent A delegates to B, which delegates to C) needs to be walkable independently of what each hop is individually permitted to touch.
