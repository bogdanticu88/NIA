# NIA threat model

This is not a marketing list of things NIA "handles." Every threat below gets checked against the actual code, function by function, and classified honestly across five questions: does NIA stop this before it happens (Prevent), notice it while or after it happens (Detect), limit or cut off the damage once noticed (Contain), leave enough evidence to reconstruct what happened afterward (Investigate), and where does none of that apply yet (Not covered). Most threats here land on more than one of these, few land on all five, and several are honestly Not covered outright. That's the point of writing this down rather than letting docs/ARCHITECTURE.md's per-component claims imply more coverage than actually exists when read together.

Scope: this is the threat model for NIA's own control plane, the identity, authorization, monitoring, and evidence layer around agents. It is not a threat model for Tessera's OpenFGA integration (see Tessera's own repo for that), and it is not a threat model for the downstream tool or MCP server itself, whatever it does with an authorized request is that tool's own security posture, not NIA's. When `NIA_GATEWAY_DOWNSTREAM_URL` is configured, NIA does forward the call and inspect what comes back for a narrow, named set of security-relevant conditions, see threat 6 below and `cmd/gateway`'s `forward.go`, this is not full response content inspection, and unconfigured (the default) the gateway still stops at the authorization decision the way it always did.

* * *

### 1. Stolen or leaked agent credential used by an attacker outside the agent

An attacker gets hold of an agent's API key or token (leaked in a log, checked into a repo, exfiltrated from wherever the agent stores it) and uses it directly, bypassing the agent's own code entirely.

**Prevent:** Now, mostly. `cmd/gateway`'s default identity resolver is `credentialResolver` (`cmd/gateway/authn.go`), a caller must present `Authorization: Bearer <credential-id>.<secret>`, the secret is checked against a stored SHA-256 digest with a constant-time comparison, and `Verify` refuses anything revoked, expired, or disabled before the request goes anywhere near authorization. A leaked credential still authenticates as the agent it belongs to, that part can't be prevented by the gateway, but the older gap, no credential required at all, is closed, see threat 2. `POST /credentials/{id}/revoke` and `niactl credential revoke` are how an operator actually responds to a suspected leak, revoked takes effect on the very next request, `Credential.Effective` is checked at verification time, not on a delay.

**Detect:** Same as before, mostly indirect, through the risk signals that would flag the agent's own compromise, `novel_tool`, risk-class weighting, sensitive-resource touches (`internal/risk.HistoryScorer`). Nothing distinguishes "the real agent doing something unusual" from "an attacker using its stolen credential doing something unusual," the identity looks identical either way, credential-backed authentication proves who's holding the secret, not whether the party holding it is supposed to be.

**Contain:** `internal/credentials.Store`'s revoke path exists and `POST /credentials/{id}/revoke` works, and `internal/monitoring.Monitor`'s `ActionRevoke` calls it for real, both `cmd/api` and `cmd/gateway` now construct a real `credentials.Store` (`credentials.FromEnv`) instead of `cmd/gateway` wiring the monitor with `nil`, so crossing the revoke threshold actually revokes credentials rather than degrading to an audited no-op. The kill switch is still the bigger hammer: `niactl kill` or an `ActionKill` from monitoring now revokes every active credential for the agent in addition to setting the policy sentinel, and `credentialResolver` independently checks `policy.Client.IsKilled` on every request, so even a credential a deployment's store somehow still shows as active cannot authenticate once its agent is killed, see docs/ARCHITECTURE.md's "Credential-backed authentication and state convergence".

**Investigate:** `internal/audit` has every allowed and denied call the credential made, under the agent's ref, and now under a specific credential too, `gateway.allowed`/`gateway.denied`/`gateway.unknown_tool` all carry `credential=<id>` in their detail string (`resolved.CredentialID`, set by `credentialResolver`). `internal/audit.Event` still doesn't carry it as its own structured field, it's in the free-text `Detail`, greppable but not queryable the way `AgentRef` is, a real gap if this trail ever needs to answer "every call this one credential made" at scale rather than by inspection.

**Not covered:** Detecting a stolen-but-still-valid credential being used by someone other than the real agent. Authentication now proves possession of the secret, it can't tell a legitimate holder from a thief who has the same secret, that's what risk-signal detection is for, and it's still indirect, see Detect above. Replay is the other half of this worth stating plainly rather than leaving implicit: `<id>.<secret>` is a bearer token, not a nonce or a challenge/response, presenting the same valid secret twice is not distinguishable from the real agent calling twice, there is no per-request freshness check anywhere in this path. A captured valid credential is reusable for its full remaining lifetime, whatever the agent could do, the thief can do, until an operator revokes it, it expires, or it's rotated out from under the thief by the legitimate holder noticing and asking for a fresh one. Rotation, expiry, and revocation are all real (see Prevent above and `internal/credentials.Credential.Effective`), replay prevention within a still-valid window is not, and isn't planned, a nonce-based scheme is a real protocol change to how agents present credentials, not a gap closeable inside this package.

* * *

### 2. Spoofed caller identity, no credential at all

Anyone who can reach `cmd/gateway` sets `X-Agent-Ref: agent:billing-reconciler` and is treated as that agent, no proof of anything required.

**Prevent:** Closed as the default. `headerResolver` still exists but no longer runs unless an operator explicitly sets `NIA_GATEWAY_INSECURE_HEADER_AUTH=1`, logged loudly at startup when it is, for local dev only; without it, `credentialResolver` doesn't read `X-Agent-Ref` at all, a bare header with no `Authorization: Bearer <id>.<secret>` gets 401, proven directly by `TestHandleToolCall_FakeAgentRefAloneNoLongerAuthenticates` in `cmd/gateway/authn_test.go`, the exact attack this threat describes, asserting the policy check was never even reached. `identity.Resolver` being an interface is what made this swap possible without touching `handleToolCall` itself.

**Detect:** `AssuranceStrong` is recorded on a credential-backed resolution now (`identity.AssuranceStrong`, up from the header resolver's `AssuranceWeak`), but same as before, nothing currently reads or acts on the assurance level itself, no signal, no audit annotation, no risk weighting keyed off it. Still plumbing for a future check, not a current one, the value it would now carry is just more meaningful.

**Contain:** Whatever containment applies to the identity, kill, revoke, applies the same as if the real agent were compromised, see threat 1. An attacker with no credential at all now gets 401 before authorization runs, there's no identity to contain because none was ever established.

**Investigate:** Same as threat 1, the audit trail records calls under whatever agent a valid credential resolved to, plus which credential (`credential=<id>` in the detail string). A rejected, uncredentialed attempt is not audited at all, `cmd/gateway`'s `handleToolCall` only writes an audit event once there's a resolved identity to attach it to, so a flood of bare, unauthenticated requests leaves no trail beyond whatever access logging sits in front of the gateway, worth stating plainly rather than implying the audit trail sees everything.

**Not covered:** This threat is about `cmd/gateway`'s tool-call path specifically. Authenticating a human operator or service calling `cmd/api` itself is a separate surface, closed separately, see threat 12's updated writeup and `internal/opauth`.

* * *

### 3. Over-privileged agent, standing grants broader than the job needs

An agent is granted every tool it might conceivably need up front, RBAC says yes to all of it, and most of that access is never exercised in normal operation, exactly the setup `niactl simulate attack -scenario agent-hijack` models on purpose.

**Prevent:** Nothing prevents an operator from over-granting, `internal/policy.WriteGrants` has no notion of least privilege or unused-grant flagging, it writes whatever it's told. This is a design and process problem, not something an authorization control plane can solve unilaterally.

**Detect:** This is what `internal/risk.HistoryScorer`'s `novel_tool` signal exists for, an agent calling a tool it's authorized for but has never used before scores as risk, over-provisioning becomes visible the first time it's actually exercised rather than staying invisible forever. `GET /graph/{id}/blast-radius` also makes the standing exposure itself visible before anything happens, an operator can query what an agent could reach through discovered relationships and get a `HIGH`/`MEDIUM`/`LOW` call on it. That result can include access the agent no longer has, the graph is historical and doesn't drop an edge when the grant behind it is revoked, see docs/ARCHITECTURE.md's "The identity graph" section, so it's a starting point for review, not a substitute for checking `internal/policy.ListGrants` for what's actually still granted.

**Contain:** The same flag/revoke/kill thresholds as any other risk-driven containment, once the excess access actually gets used.

**Investigate:** `internal/audit` and `internal/incident` both show exactly which grant got exercised and when. `internal/graph`'s reachability query can answer "what else could this agent have reached" as part of a post-incident review, not just what it did reach.

**Not covered:** Proactive least-privilege enforcement, there's no "flag grants nobody has used in 90 days" report or anything like it. This is a real, scoped gap, not a placeholder for something claimed elsewhere.

* * *

### 4. Compromised agent escalating through tools it's authorized for but rarely uses

The agent's own reasoning is hijacked, through a prompt injection, a poisoned input, a compromised dependency, whatever the mechanism, and it starts calling tools that are technically within its granted permissions but outside its normal behavior.

**Prevent:** Not by NIA, this is upstream of what an authorization and monitoring layer can stop, the call is authorized, that's the premise of the scenario.

**Detect:** This is the core thing `internal/risk.HistoryScorer` is built for. `novel_tool` catches a tool the agent has never called before, the risk-class-weighted signal catches escalation toward destructive tools specifically, and `internal/monitoring.Monitor` accumulates these into a running per-agent total rather than judging each call alone, so a sequence of individually-small-looking escalations still adds up. `niactl simulate attack -scenario agent-hijack` demonstrates exactly this pattern end to end.

**Contain:** Real, not simulated. Crossing the kill threshold calls `internal/policy.Kill`, which is confirmed against a live Tessera/OpenFGA stack to actually deny the next request, not just log that it would have. Crossing the flag threshold currently only audits, it doesn't reduce access, that's an honest gap, flag is a signal for a human to look at, not an automatic containment action today.

**Investigate:** `internal/incident` records the exact signals, weights, and cumulative total that triggered containment, and `GET /graph/{id}/blast-radius` on the agent shows what it could still have reached had containment not fired.

**Not covered:** Detection here is signature-free but still shallow, three signals (novel tool, risk class, sensitive resource), not the fuller privilege-deviation or sequence-anomaly detection the original engineering directive called for, both still open per the roadmap in the project's implementation assessment. `CENTIPEDE`-style anomaly detection replacing `HistoryScorer` outright is still an intent, not code.

* * *

### 5. Compromised agent exfiltrating a sensitive field through a tool it's authorized to call

The agent is legitimately allowed to call `database.query`, but an attacker directs it to query a column, `customers.ssn`, that goes well beyond what its normal job touches.

**Prevent:** Real, not just detected after the fact. When `NIA_GATEWAY_RESOURCE_RULES_PATH` is set, `ArgumentResourcePolicy` (`cmd/gateway/resources.go`) turns the call's arguments into resource names, and anything `internal/sensitivity` classifies `sensitive` or above needs its own `policy.GrantForData` grant, checked and denied separately from the tool-level grant if missing, `gateway.denied` naming the specific resource. This is the Agent+Tool+Resource decision, not only Agent+Tool, and `niactl simulate attack`'s own transcript shows a real 403 on exactly this pattern.

**Detect:** `internal/risk.HistoryScorer`'s `sensitive_resource` signal adds to the risk total the same call already crossed the data-grant check for, or, if the resource wasn't classified sensitive enough to require its own grant, at least contributes to the running total.

**Contain:** Immediate for a classified resource, the request is denied in that same call, not after review. For an unclassified but actually-sensitive resource nobody wrote a rule for, containment falls back to the general risk-accumulation path in threat 4.

**Investigate:** The audit event names the specific resource denied, not just the tool. `internal/incident` records don't currently carry the resource name in a structured field, only inside the free-text reason and signal names, a real gap for tooling that wants to query "which incidents involved this specific column" directly rather than grepping.

**Not covered:** Anything not named in `NIA_GATEWAY_RESOURCE_RULES_PATH`'s rules. `internal/sensitivity` is a flat, explicit rule list on purpose, explainable over inferred, which means an unclassified resource is silently `public` and gets no extra check at all, a real and deliberate tradeoff, not an oversight, see the package's own doc comment.

* * *

### 6. Malicious or compromised tool, or a compromised MCP server

The tool an agent calls, or the MCP server fronting it, is itself malicious or compromised, and returns attacker-controlled output back to the agent, or silently does something other than what its registration claims.

**Prevent:** Registration-time only, unchanged by the forwarding work below. `internal/registry/tools` requires a tool to be registered with a declared risk class before the gateway's catalog check (`NIA_TOOLS_API_URL`) will let a call through at all, so an entirely unregistered tool is rejected outright. Nothing verifies that a registered tool's actual behavior matches its declared risk class, or that its MCP endpoint is what it claims to be, that's a trust relationship with whoever registered it, not something NIA independently verifies. Forwarding to a real downstream doesn't change this, an authorized call still reaches whatever is actually configured at `NIA_GATEWAY_DOWNSTREAM_URL`, real or compromised, the gateway has no independent way to tell the difference before the call goes out.

**Detect:** Partial now, where before this pass it was none at all. When `NIA_GATEWAY_DOWNSTREAM_URL` is set, `cmd/gateway`'s `HTTPForwarder` actually forwards the call and `inspectAndAuditDownstream` looks at what came back for three specific things: the downstream's own HTTP status (5xx audited as `gateway.downstream_error`, 4xx as `gateway.downstream_rejected`), a top-level JSON `"error"` field in the body even on a 200 (`gateway.downstream_reported_error`), and a response that hit the 10 MiB read cap (`gateway.downstream_response_truncated`, worth a look on its own, a tool suddenly returning far more data than usual is a signal regardless of whether anything else about the call looked wrong). This is a named, narrow set of checks, not general content inspection, NIA has no way to know a response is malicious just because it parses and returns 200, a tool that returns plausible-looking poisoned output gets none of these signals raised.

**Contain:** Still N/A for the response content itself, nothing here stops a compromised tool from returning bad data to an agent that then acts on it, that's downstream of NIA's authorization boundary. What NIA can and does contain is access to the tool going forward: the same credential revoke and kill paths used everywhere else apply here too, an operator who identifies a compromised tool can deny it by killing or restricting the agents authorized to call it, not by anything specific to this threat.

**Investigate:** Meaningfully better than before. Every forwarded call's audit trail now carries the downstream's status code, response size, and duration alongside the existing agent/tool/credential fields (see the `detail` string on every `gateway.downstream_*` action), and `resp["result"]` in the gateway's own response is the actual downstream body, not a stand-in, so a caller and an incident review both see the same thing. Still not captured: the response body itself isn't written into the audit trail, only its metadata, recovering exactly what a compromised tool returned to a specific call means correlating the audit timestamp with whatever logging the downstream itself kept, NIA doesn't retain tool response bodies.

**Not covered:** Full content inspection of tool responses, semantic detection of a subtly poisoned but well-formed answer, and anything about a downstream when `NIA_GATEWAY_DOWNSTREAM_URL` isn't set, the default, in which case this threat is exactly as uncovered as it was before this pass.

* * *

### 7. Agent-to-agent trust and delegation abuse

A compromised or malicious agent uses a `trusts` or `delegates_to` relationship to reach a more privileged agent, or to have another agent act on its behalf beyond what was intended.

**Prevent:** Not yet. `internal/graph` records `trusts` and `delegates_to` edges, `POST /graph/edges` and `niactl graph add-edge`, and they're queryable, but `internal/policy`'s live authorization check does not consult the graph at all, a `delegates_to` edge doesn't change what OpenFGA allows. This is documented plainly in docs/ARCHITECTURE.md's Delegation row, not a silent gap.

**Detect:** Only as bookkeeping. `GET /graph/{id}/reachable` or `blast-radius` following `delegates_to` and `trusts` edges will show a delegation chain if someone queries for it, nothing runs that query proactively or flags an unusual delegation pattern.

**Contain:** Whatever the receiving agent's own grants and risk thresholds provide, the delegation relationship itself has no separate containment lever, killing the delegating agent doesn't automatically constrain what the delegate can still do, since the delegate's authorization was never actually conditioned on the delegation edge in the first place.

**Investigate:** The graph can answer "what did this agent trust or delegate to" after the fact, useful for scoping an incident's blast radius even though it wasn't enforced live.

**Not covered:** Live enforcement of trust and delegation. Closing this needs `delegate` layered onto OpenFGA as a relation Tessera's own checks understand, so a delegation edge actually changes what the gateway allows rather than only what the graph reports, tracked as open work, not attempted in this pass.

* * *

### 8. Kill switch bypass, a killed agent continuing to act

Whether through a race, a cached decision, or a second policy-engine instance that didn't see the kill, a killed agent's calls keep getting allowed.

**Prevent:** The core invariant holds by design: `InMemoryClient.Check` and Tessera's own `CheckAsync` both consult the kill sentinel before anything else, sentinel-first, and `Kill` clears grants at the same time it sets the sentinel so a concurrent grant write can't land after a kill and resurrect access. There is no cache on the hot path, `internal/policy.Check` is a live, per-request call every time, confirmed end to end against a real Tessera/OpenFGA stack: kill, then check, denied, real tuples deleted from a real store. `cmd/gateway/concurrency_test.go`'s `TestHandleToolCall_ConcurrentRequestsDuringKill_NoRequestSucceedsAfterKillCompletes` makes the specific "race" version of this threat concrete: fifty goroutines fire tool-call requests concurrently with a real `Kill` call, and the only property asserted is that once `Kill` has returned, every subsequent request is denied, a request that happened to land on either side of the kill mid-flight isn't the bug, one that succeeds after the kill has already completed would be.

**Detect:** N/A within a single, correctly-running instance, prevention is the mechanism here, not detection after the fact.

**Contain:** N/A, follows from Prevent holding.

**Investigate:** `internal/audit` records the kill event itself (`agent.killed`) and every subsequent `gateway.denied` for that agent, a clean before/after in the trail.

**Not covered:** Multi-replica correctness. `TesseraHTTPClient`'s read-modify-write grant reconciliation only serializes within one client instance, and if more than one `cmd/api` or `cmd/gateway` process talks to the same Tessera/OpenFGA backend concurrently, a kill from one instance racing a grant write from another isn't proven safe, this needs Tessera-side advisory locking, already on Tessera's own roadmap, and is tracked as an explicit, ongoing gap rather than solved inside NIA's repo, see docs/ARCHITECTURE.md's Integration plan section. This is the one threat on this list where the single-instance answer is genuinely strong and the multi-instance answer is genuinely unverified, worth keeping those two facts separate rather than letting the first imply the second.

* * *

### 9. Audit trail tampering or silent loss

An attacker with database access to the audit store, or a bug, deletes or alters records to cover tracks, or the audit write itself silently fails and nobody notices.

**Prevent:** Nothing stops a write. This is fundamentally not a preventable threat with an append-oriented model, and this pass didn't try to make it one: `internal/audit.PostgresSink` is still a plain table anyone with write access to that Postgres instance can `UPDATE` or `DELETE` against directly. What changed is that doing so no longer goes undetected, see Investigate below, evidence after the fact rather than prevention is the actual, honest target for this threat.

**Detect:** For the tampering half, now yes, where before this pass there was nothing at all. `internal/audit/chain.go`'s hash chain, every event's hash computed from its own data plus the previous event's hash, both stored alongside it, means `GET /audit/verify` (`niactl audit verify`) can be run at any time and will name exactly which event was modified, or exactly where a deletion, insertion, or reordering broke the link between two consecutive entries, see `docs/ARCHITECTURE.md`'s new "Tamper-evident audit" section for the full mechanism. This is detection on demand, not continuous monitoring, nothing calls `Verify` automatically today, an operator or a scheduled job has to run it. For the failure-to-write case, unchanged: `s.audit()` in `cmd/api` and the gateway's own `audit()` helper both log an append failure and continue, the action they're recording already succeeded either way, a deliberate fail-open choice, but still only a log line, not an alert.

**Contain:** Still N/A for the tampering itself, this threat is about the evidence trail, not an ongoing action to stop. What changed: an operator who runs `niactl audit verify` and gets a break back now has grounds to treat every event from that point in the chain onward as untrustworthy for this specific incident, evidence a review can act on, where before there was no way to even suspect tampering had happened short of noticing records that just felt wrong.

**Investigate:** Meaningfully better, this was the weakest category before this pass and is the one this pass actually targeted. `Verify`'s `VerifyResult` names the exact event (by its storage-layer sequence number) and the exact reason, a hash mismatch versus a broken chain link, an incident review no longer has to take the trail's cleanliness on faith. Still true: an attacker who correctly recomputes every hash after the point they tampered, not just their own forged or modified row, defeats this, hash chaining proves internal consistency, it can't prove the whole table wasn't replaced by someone who understood the algorithm and did the work. That's not a gap this pass missed, it's the stated boundary, see the callout in `docs/ARCHITECTURE.md`'s new section and `internal/audit/chain.go`'s own doc comment:

> Hash chaining provides tamper evidence.
> It does not by itself prevent a privileged database administrator
> from rewriting both the events and the chain.

**Not covered:** Append-only storage guarantees at the database level (Postgres itself still allows `UPDATE`/`DELETE` against this table, nothing here revokes that), write-path alerting beyond a log line, a fail-closed mode for audit writes, automatic or continuous chain verification (today it's an on-demand operation, not a background job or an alert), and, most importantly, an external anchor: a periodic signed checkpoint published somewhere the database itself can't reach, or WORM storage for the table, either of which would be what actually closes the "privileged rewrite" gap named above. Neither exists yet, `internal/audit.Chained` is deliberately the narrow interface such a mechanism would consume, so adding one later doesn't mean redesigning this API, only adding a second reader of it.

* * *

### 10. High-volume or resource-exhaustion abuse by a compromised agent

A compromised agent calls tools rapidly, far outside its normal request volume, either to exfiltrate data fast before it's caught or simply to run up cost and load.

**Prevent:** None. No rate limiting exists anywhere in `cmd/gateway`.

**Detect:** None currently. `internal/risk.Signal`'s own doc comment names `volume_deviation` as an intended future signal, but `HistoryScorer` doesn't implement it, there's no request-rate tracking in this codebase to detect a burst against.

**Contain:** Indirect only, if the burst happens to also trip `novel_tool` or a sensitive-resource check, normal containment applies, but a burst of calls to tools the agent already uses normally would sail through today.

**Investigate:** `internal/audit` has a timestamped record of every call, so a burst is visible after the fact to anyone who thinks to look at call frequency, nothing surfaces it proactively.

**Not covered:** This entire threat category. Named directly rather than folded into a vaguer "risk scoring covers behavioral anomalies" claim, it doesn't, not this one, yet.

* * *

### 11. Concurrent control-plane instances racing each other

More than one `cmd/api` or `cmd/gateway` process, or more than one `Tessera.Service` instance, handles requests against the same backing store at the same time.

**Prevent:** Verified now for the state that actually gates a decision, where it was previously unverified in either direction. `docs/ARCHITECTURE.md`'s "Distributed state" section has the full store-by-store review; the short version is that kill state (through Tessera or, locally, `policy.InMemoryClient`), credential state (`NIA_CREDENTIALS_DATABASE_URL`), and, as of this pass, risk enforcement state (`NIA_RISK_DATABASE_URL`, `internal/monitoring.RiskStore`) are all safe to share across replicas: `PostgresRiskStore.Accumulate` is a single UPSERT, Postgres's own row locking serializes two replicas racing to score the same agent, and `cmd/gateway/distributed_test.go` proves two independent `*gateway` values sharing those three stores converge on the same authorization decision. Verified against real infrastructure too, not just the in-process test: two real `nia-gateway` processes, a real Tessera instance, and a real Postgres database, splitting one agent's risk-generating calls across both processes, crossing the kill threshold on the second process, and confirming the first process, which never called `Kill` itself, denied the agent's very next request. One real gap this same live run surfaced: `PostgresRiskStore`'s (and every other `PostgresX`'s) `CREATE TABLE IF NOT EXISTS` schema creation is not itself safe against two brand-new processes racing to create the same table for the first time against a fresh database, hit directly during this verification (`pq: duplicate key value violates unique constraint "pg_type_typname_nsp_index"`), transient and harmless once the table exists, but real: a deployment bringing up multiple replicas simultaneously against a database that's never seen this schema before can hit it. Not fixed in this pass, staggering first startup or running schema creation once, out of band, before scaling up avoids it, see docs/ARCHITECTURE.md's own note on this.

**Detect, Contain:** Same posture as before for what's still genuinely process-local: `internal/incident.InMemoryStore` and `cmd/gateway`'s in-memory incident store are still process-local, a second gateway replica still wouldn't see the first one's structured incident records, even though the risk total and the kill/credential state that decision was based on are now shared correctly. `internal/registry.InMemoryAgentRegistry` (`cmd/api`'s own agent metadata cache, owner/purpose/state) is also still process-local, though `GET /agents/{ref}`'s `EffectiveState` already live-queries the shared kill state on every read rather than trusting the cache, see docs/ARCHITECTURE.md's "State convergence" section, so a stale cache never produces a wrong authorization outcome, only a possibly-stale `State` field alongside an always-live `EffectiveState` one.

**Investigate:** Whatever each individual instance's own audit and incident records show. The audit trail itself is safe to share (`NIA_AUDIT_DATABASE_URL`, both processes writing into one hash chain, see `internal/audit`), so a shared audit deployment already gets cross-instance correlation there; incident records specifically do not, two replicas' worth of incident records for the same agent aren't merged or reconciled anywhere.

**Not covered:** `internal/incident`'s own process-local storage, closing it needs the same kind of `PostgresX` backend this pass added for risk state, scoped out here to keep this pass's changes bounded to what the directive named as security-critical, incident records are evidentiary, not decision-gating. OpenFGA/Tessera-side locking under sustained concurrent write load (grant writes racing each other, not reads) also remains outside what NIA's own repo can verify, see docs/ARCHITECTURE.md's Integration plan section.

* * *

### 12. An operator misusing the control plane itself

Someone with legitimate `niactl`/`cmd/api` access, a human operator, grants excessive access, kills the wrong agent, or issues credentials they shouldn't, whether by mistake or by insider intent.

**Prevent:** Authentication exists now, authorization still doesn't. `internal/opauth` gives `cmd/api` a real, checkable notion of who is calling, a static, admin-managed list of bearer tokens (`NIA_OPERATOR_TOKENS_PATH`), verified with a SHA-256 comparison the same way `internal/credentials` verifies an agent credential, wired in as `operatorAuthMiddleware` in front of every route except `GET /healthz` and `GET /metrics` when it's configured. As of the gap-closing pass this is no longer opt-in: `opauth.FromEnvEnforced` makes an unset `NIA_OPERATOR_TOKENS_PATH` a startup failure for both `cmd/api` and `cmd/gateway`, and running open takes a deliberate `NIA_ALLOW_UNAUTHENTICATED=1` that both processes log loudly. The old default mattered more than it looked: `deployments/docker-compose.yml` never set the variable, so the reference stack shipped with agent registration, grant writes, credential issuance, kill, restore, and the audit trail reachable by anyone who could reach port 8080. That file now mounts a tokens file into both services. Authenticated, though, this stops short of solving the threat: every valid token can still do everything `cmd/api` exposes, register agents, write grants, issue credentials, kill or restore anything, there's no RBAC, no scoping, no distinction between operators once authenticated. `TesseraHTTPClient`'s own doc comment notes a related, narrower gap this doesn't touch either: most calls other than Kill still authenticate to Tessera as a configured system identity rather than the real, now-known operator, `Client.Restore` and the others still carry no operator parameter to sign with.

**Detect:** Not proactively, an unusual pattern of operator actions (mass grants, rapid credential issuance) isn't flagged, only visible to someone manually reviewing the audit trail. Now at least attributable to a specific, authenticated operator when opauth is configured, see Investigate below, detection over that attribution still doesn't exist.

**Contain:** N/A, no separate operator-action containment lever exists distinct from the mechanisms already covering agents (a bad grant can be deleted, a bad kill can be restored). A compromised or misused operator token can be contained the same coarse way any static credential is, remove it from the tokens file and restart `cmd/api`, `internal/opauth.Store` has no live revoke the way `internal/credentials.Store` does, see that package's own doc comment for why that's a stated, accepted gap rather than something worth building before there's a real need for it.

**Investigate:** Every registration, grant, credential, and kill/restore action writes to `internal/audit`, `niactl kill` already requires an `-incident` string, and `internal/audit.Event` now records who did it reliably when opauth is configured: `resolveOperator` (`cmd/api/opauth.go`) uses the authenticated token holder's name in preference to whatever the request body's `operator`/`*_by` field claims, so the audit trail can no longer be made to say the wrong name just by lying in the request. Unconfigured, this is unchanged from before, the audit trail shows whatever the caller claimed, no better or worse than it always was.

**Not covered:** Per-operator authorization on the control plane's own API (RBAC, scoping one token to a subset of what `cmd/api` exposes), token rotation or expiry, and any anomaly detection over operator behavior itself. Authentication is real now; NIA still does not secure who gets to configure NIA beyond "holds a valid token or doesn't."

* * *

### What this document is not

This is not a claim that every threat above is fully handled, several are explicitly Not covered, and several land on Prevent only because the specific mechanism (the kill switch, the data-grant check) happens to be real, not because the surrounding category is solved. It should be re-read and re-scored honestly as coverage changes, the same discipline docs/ARCHITECTURE.md's own "What this scaffold is, and isn't" section applies to individual components, applied here at the threat level instead.
