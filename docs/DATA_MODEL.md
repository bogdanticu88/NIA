# NIA data model: the identity graph

This is the detail behind the identity graph section of `ARCHITECTURE.md`. It covers the node and edge types NIA tracks, and how they relate to the two other places identity-shaped data lives in this system: the agent registry (`internal/registry`) and the policy engine's tuple store (Tessera, via `internal/policy`).

## Why there are three places identity data lives, not one

This looks like duplication and isn't. Each of the three answers a different question, at a different speed, and none of them can answer the other two well.

The agent registry answers "does this identity exist, and what's its current lifecycle state." It's a simple keyed lookup, and it's what `cmd/api` and `cmd/gateway` both consult first.

OpenFGA, through Tessera, answers "can this identity do this specific thing, right now." It's a live, per-request check with no cache, because that's what makes the kill switch instant.

The identity graph answers "everything this identity could reach, directly or transitively." It's a traversal, not a lookup or a point check, and it's slower and heavier than either of the other two. You query it during onboarding review, permission design, and incident response, not on every tool call.

## Nodes

| Kind | Represents | Example |
|---|---|---|
| `Human` | A person accountable for one or more agents | `human:bogdan` |
| `Agent` | A non-human identity: an agent, service account, or automated process | `agent:billing-reconciler` |
| `Tool` | Something an agent can call | `tool:invoice-api` |
| `Data` | A data resource an agent can reach, directly or through a tool | `data:customer-pii` |
| `Credential` | A credential issued to an agent | `cred:a1b2c3` |

`Agent` nodes here are the same canonical ref as `identity.AgentRef` in the registry, the graph doesn't mint its own identity namespace, it references the registry's.

## Edges

| Kind | From → To | Meaning |
|---|---|---|
| `owns` | Human → Agent | Who's accountable if this agent misbehaves |
| `delegates_to` | Agent → Agent | Agent A can act on Agent B's behalf, time-bounded |
| `trusts` | Agent → Agent | Agent A accepts calls originating from Agent B |
| `member_of` | Agent → group | Same shape as Tessera's `bu_group` membership |
| `grants` | Agent → Tool \| Data | Mirrors a live grant in the policy engine |
| `bound_to` | Credential → Agent | Which agent a credential belongs to |

`grants` edges are redundant with what Tessera/OpenFGA already knows, and that's intentional. They're written to the graph right after they're written to the policy client (`cmd/api`'s grant handler calls `WriteGrants` first, then adds the matching graph edge once that succeeds), so the graph has a complete picture for traversal without querying OpenFGA node by node, which OpenFGA's tuple model isn't built for efficiently at graph scale. `owns`, `delegates_to`, `trusts`, and `member_of` still have no automatic source, nothing in the registry or policy client produces any of the four, so they're added by hand through `POST /graph/edges` / `niactl graph add-edge` until something does. `bound_to` is automatic too, issuing a credential adds the `Credential` node and the edge to its agent in the same call.

Deleting a grant does not remove its edge, and that's a deliberate design choice, not a missing feature. `Graph` has no edge-removal method by design, see `internal/graph`'s package doc comment for the full reasoning: the graph is meant to answer "what has this identity ever been connected to," a historical, append-only record, not "what does it have access to right now." `internal/policy.Check`/`ListGrants` is the only source of truth for exactly what's granted right now, always, and no code in this repo reads graph reachability as a live permission list. `cmd/api/graph_test.go`'s `TestGraphEdgeSurvivesGrantDeletion_ButPolicyCheckReflectsCurrentTruth` demonstrates the two staying independent, an edge surviving in the graph after `internal/policy` has already denied the underlying grant.

## The query that matters most: blast radius

Given a compromised or suspect agent, `Graph.Reachable` answers: starting from this agent, and following `delegates_to`, `trusts`, and `grants` edges transitively, what else is reachable. That set is your blast radius, and it's the thing you want on screen in the first sixty seconds of an incident, before deciding whether a `Kill` (via `internal/policy`) needs to cascade to more than one agent.

`GET /graph/{id}/blast-radius` (`niactl graph blast-radius`) is `Reachable` plus the summary an incident review wants first rather than a raw node list to eyeball: total count, a count by node kind, which reachable `Data` nodes classify `sensitive` or `critical` through `internal/sensitivity`, and a `HIGH`/`MEDIUM`/`LOW` severity call. The rule is fixed, not learned: `HIGH` when anything reachable is critical or five-plus reachable nodes are agents or tools, `MEDIUM` when anything reachable is sensitive or at least one reachable node is an agent or tool, `LOW` otherwise. See `ARCHITECTURE.md`'s identity graph section for the full reasoning behind that rule.

This is also why `delegates_to` is modeled as its own edge kind instead of folded into `grants`: a delegation chain (agent A delegates to B, which delegates to C) needs to be walkable independently of what each hop is individually permitted to touch.
