# NIA security invariants

An invariant here is a specific, checkable claim about what NIA guarantees, stated precisely enough that a test can either confirm it holds or prove it doesn't. This is different from docs/THREAT_MODEL.md, which asks "does this threat get handled" across five broad categories; this document asks "what exactly does NIA promise, and where's the test." Several invariants below are fail-open by design, stated that way on purpose rather than treated as bugs, the distinction that matters is between a fail-open posture that was decided and tested, and one that was never decided at all, silently wrong. Two items that used to be the second kind got fixed in this pass specifically so they could move to the first, see invariants 6 and 7 below.

* * *

### 1. Kill denies every subsequent check, unconditionally

Once an agent is killed, every `policy.Check` call for that agent returns `false`, regardless of what grants exist for it, until it's explicitly restored.

**Enforced:** `InMemoryClient.Check` and Tessera's `CheckAsync` both consult the kill sentinel before anything else. `InMemoryClient.Kill` sets the sentinel and clears the agent's grants in the same call, sentinel-first, so a concurrent grant write can't land after a kill and resurrect access.

**Tested:** `internal/policy/policy_test.go`'s `TestKillDeniesEvenPriorGrants` (a killed agent with standing grants still gets denied) and `TestReconcileNeverResurrectsAKill` (a reconcile call after a kill doesn't restore access). Confirmed a second way, against a real backend, not just the in-memory reference: registered against a live Tessera-plus-OpenFGA stack, checked as allowed, killed, checked again as denied, real tuples deleted, see docs/ARCHITECTURE.md's "Integration plan for Tessera" section. `cmd/gateway/concurrency_test.go`'s `TestHandleToolCall_ConcurrentRequestsDuringKill_NoRequestSucceedsAfterKillCompletes` covers the case this section used to flag as unverified, fifty concurrent requests racing a real `Kill` call, asserting only that no request succeeds once `Kill` has actually returned, not that a request racing it gets any particular outcome.

**Status:** Holds, in both the in-memory reference and the real Tessera integration, single-instance and, for the case that actually matters for a real deployment, across replicas too: kill state is `policy.Client`-backed (Tessera, or `policy.InMemoryClient` locally), shared across every `cmd/api`/`cmd/gateway` process pointed at the same Tessera instance, see docs/ARCHITECTURE.md's "Distributed state" section for the full review and the live two-process verification behind it. What's genuinely not covered: concurrent replicas of Tessera itself, or OpenFGA itself, both are treated as a single trusted backend this codebase talks to over HTTP, their own internal replication and consistency guarantees are outside this repo.

* * *

### 2. Restore clears the kill sentinel and nothing else

Restoring a killed agent clears the sentinel so future checks can succeed again, but does not implicitly re-grant anything, whatever was granted before the kill (and survived it, see invariant 1) is what's available after restore.

**Enforced:** `InMemoryClient.Restore` deletes the sentinel entry only, it never touches the grants map.

**Tested:** `internal/policy/policy_test.go`'s `TestRestoreClearsKillSentinel`.

**Status:** Holds.

* * *

### 3. A mutating grant call against a killed agent fails outright, it does not silently no-op

`WriteGrants` and `DeleteGrants` against a killed agent return `ErrKilled` rather than either succeeding (which would be misleading, the agent is still denied regardless) or silently discarding the call.

**Enforced:** Both `InMemoryClient` and `TesseraHTTPClient` check the kill sentinel before attempting the mutation and return `ErrKilled` immediately if it's set. `cmd/api`'s `handleWriteGrants` maps `ErrKilled` to 409, not 500, telling the caller specifically what's wrong rather than a generic failure.

**Tested:** `internal/policy/tessera_client_test.go`'s `TestWriteGrants_AgainstKilledClient_ReturnsErrKilledWithoutCallingOnboard` and `TestWriteGrants_KilledConcurrentlyBetweenReadAndWrite_ReturnsErrKilled` (the kill lands mid-reconcile, between the read and the write, and the write still correctly fails rather than racing ahead).

**Status:** Holds.

* * *

### 4. Risk accumulates per agent and resets only on a kill

`internal/monitoring.Monitor` keeps a running total per agent ref, comparing the total against thresholds rather than each call's own score in isolation, and only a kill resets it, a flag or a revoke leaves the running total exactly where it was.

**Enforced:** `Monitor.Observe` calls `m.risk.Accumulate(ctx, agentRef, value)` (`internal/monitoring/risk_store.go`'s `RiskStore` interface), only resetting it via `m.risk.Reset(ctx, agentRef)` inside the `ActionKill` branch. The running total itself moved out of `Monitor` and into this interface as of the state-distribution pass, see invariant 16 below, `InMemoryRiskStore`'s own mutex-protected map preserves the original single-process behavior this invariant describes, `PostgresRiskStore` extends the same accumulate-and-reset contract across processes.

**Tested:** `internal/monitoring/monitoring_test.go`'s `TestObserve_RiskAccumulatesAcrossCalls_CrossesThresholdOnTheThirdCall`, `TestObserve_RiskAccumulationIsPerAgent` (agent B's calls don't affect agent A's total), `TestObserve_KillResetsCumulativeRisk`, `TestObserve_RevokeDoesNotResetCumulativeRisk`, and `TestObserve_RiskAccumulationIsRaceSafe` (fifty concurrent `Observe` calls for one agent, checked afterward that the total lost no updates, `go test -race` run against it). `internal/monitoring/risk_store_test.go`'s `TestInMemoryRiskStore_ConcurrentAccumulateNeverLosesAnUpdate` covers the same property at the store level directly.

**Status:** Holds, including under concurrent calls to the same running process. Whether two separate gateway replicas share one total or each keep their own now depends on configuration, `NIA_RISK_DATABASE_URL` set or unset, this invariant is about the accumulate-and-reset bookkeeping being race-safe regardless of which `RiskStore` backs it, invariant 16 below is the one about multiple processes agreeing on one total.

* * *

### 5. Crossing the kill threshold actually kills, not just audits

When `Monitor.Observe`'s cumulative total crosses the configured kill threshold, it calls `policy.Kill` for real and the next request for that agent is actually denied, this is not simulated or logged-only.

**Enforced:** `Monitor.Observe`'s `ActionKill` branch calls `m.policy.Kill(...)` directly.

**Tested:** `internal/monitoring/monitoring_test.go`'s `TestObserve_KillThreshold_CallsPolicyKillAndAudits`, and end to end through the real gateway, `cmd/gateway/gateway_test.go`'s `TestHandleToolCall_AllowedCallCrossingKillThreshold_TriggersMonitoringKill`, plus `niactl simulate attack -scenario agent-hijack`'s own transcript, which shows a tool the agent successfully called earlier in the run getting a real 403 later, because `policy.Check` now reads the kill sentinel, not because the request changed, see `cmd/niactl/simulate_test.go`'s `TestRunScenario_DrivesRealSetupCallsAndDetectsContainment`.

**Status:** Holds.

* * *

### 6. A registry mirror-update failure after a kill does not block the kill (fixed this pass)

`handleKill` calls `policy.Kill` first, that's the action that actually matters, and then updates the local agent registry's lifecycle state to reflect it. If that second, purely-local update fails, the kill itself must still have gone through and the handler must still report success.

**Enforced:** `cmd/api`'s `handleKill` now logs a `SetState` failure and continues, rather than the prior code, `_ = s.agents.SetState(...)`, which discarded the error with no log line at all, a real bug, not a deliberate posture, fixed in this pass. The distinction from invariant 7 below matters: this fix didn't introduce fail-open behavior, `handleKill` was already fail-open here (the discarded error meant a failure was silently ignored either way), what changed is that the failure is now visible instead of invisible.

**Tested:** `cmd/api/invariants_test.go`'s `TestHandleKill_RegistrySetStateFails_KillStillSucceeds`, using a `failingSetStateRegistry` test double, asserts both that the HTTP handler still returns 200 and that `policy.IsKilled` genuinely reports the agent as killed afterward, not just that the response code looked right.

**Status:** Holds as of this pass. Previously an undocumented silent-discard, now a documented, logged, tested fail-open.

* * *

### 7. Registration and tool registration return 500 for an unexpected backend failure, not a false 409 (fixed this pass)

`handleRegisterAgent` and `handleRegisterTool` must return 409 Conflict only for an actual duplicate (`registry.ErrAlreadyRegistered` / `tools.ErrAlreadyRegistered`), and 500 for any other failure. The prior code mapped every error from `Register` straight to 409, harmless only because the in-memory reference implementations never returned anything else, wrong the moment either is backed by something real that can fail other ways, a database timeout reported to the caller as "you already registered this" is actively misleading.

**Enforced:** Both handlers now check `errors.Is(err, ...ErrAlreadyRegistered)` before choosing the status code.

**Tested:** `cmd/api/invariants_test.go`'s `TestHandleRegisterAgent_UnexpectedRegistryError_Returns500NotConflict` and `TestHandleRegisterTool_UnexpectedCatalogError_Returns500NotConflict` (each with an always-failing test double that never returns the duplicate sentinel), plus `TestHandleRegisterAgent_ActualDuplicate_Returns409` as the control, proving the fix narrowed the mapping rather than removing the 409 path entirely.

**Status:** Holds as of this pass.

* * *

### 8. An audit write failure never blocks the action it was recording (fail-open, by design)

Every security-relevant action, a registration, a kill, a grant, a credential issuance, is expected to produce an audit event, but if the audit write itself fails, the action it's recording has already succeeded and the request must still report that success. This is deliberately fail-open, not fail-closed: refusing a kill because the audit database happened to be unreachable at that moment would be a worse outcome for a security control plane than a kill that goes through with a gap in the trail.

**Enforced:** `cmd/api`'s `s.audit()` and `cmd/gateway`'s equivalent helper both log an append failure (`log.Printf`) and return, the caller never checks their result.

**Tested:** Previously stated in prose only, in docs/ARCHITECTURE.md and the project's implementation assessment, never actually exercised by a test, closed in this pass: `cmd/api/invariants_test.go`'s `TestHandleKill_AuditWriteFails_KillStillSucceeds`, using a `failingAuditStore` test double, asserts the kill still returns 200 and `policy.IsKilled` still reports true.

**Status:** Holds, and is now proven rather than only claimed. The corresponding gap is real and stated plainly, not softened here: an audit outage produces no alert, only a log line an operator has to be watching for, see docs/THREAT_MODEL.md's threat 9.

* * *

### 9. An identity-graph write failure never blocks the registration, credential, or grant it was recording (fail-open, by design)

Agent registration, tool registration, credential issuance, and grant writes all auto-populate the identity graph as a side effect (see docs/ARCHITECTURE.md's identity graph section). If that graph write fails, the primary action must still succeed, the graph is a second, traversal-optimized way of recording a fact the control plane already knows, not the source of truth for whether that fact is true.

**Enforced:** `graphAddNode`, `graphAddEdge`, and `graphAddGrantEdges` in `cmd/api/main.go` all log a failure and return without propagating it to their callers.

**Tested:** Previously untested, closed in this pass with `cmd/api/invariants_test.go`'s `TestHandleRegisterAgent_GraphWriteFails_RegistrationStillSucceeds`, `TestHandleWriteGrants_GraphWriteFails_GrantStillSucceeds`, and `TestHandleIssueCredential_GraphWriteFails_IssuanceStillSucceeds`, each using a `failingGraph` test double and each asserting on the primary action's actual effect (the agent is genuinely registered, the grant genuinely authorizes, the credential genuinely exists), not just the HTTP status code.

**Status:** Holds, and is now proven rather than only claimed.

* * *

### 10. An incident-store write failure never blocks the containment decision it was recording (fail-open, by design)

When `Monitor.Observe` decides to flag, revoke, or kill, it also writes an `internal/incident` record. If that write fails, the containment decision itself, the part that actually protects anything, must still have taken effect.

**Enforced:** `Monitor.Observe` folds an `incidents.Create` error into the audit event's `Detail` string rather than failing the containment decision.

**Tested:** `internal/monitoring/monitoring_test.go`'s `TestObserve_IncidentCreateError_StillCompletesAndAudits`, using a `failingIncidentStore` test double, confirms the containment action (kill, in that test) still happens despite the incident write failing.

**Status:** Holds. Three fail-open postures, audit writes (invariant 8), graph writes (invariant 9), and incident writes (this one), are the same pattern applied in three places for the same underlying reason, worth naming as one pattern rather than three separate decisions, which is part of why this document exists.

* * *

### 11. A gateway request without a valid, active credential for a non-killed agent never reaches authorization

Before `policy.Check` runs, the caller must present `Authorization: Bearer <credential-id>.<secret>` for a credential that exists, whose secret matches, whose `Effective(now)` status is `Active`, and whose owning agent is not killed. Any other case, no header, wrong scheme, malformed token, unknown id, wrong secret, revoked, expired, disabled, or a killed owning agent, resolves to no identity at all, and `handleToolCall` returns 401 without ever calling `policy.Check`.

**Enforced:** `cmd/gateway/authn.go`'s `credentialResolver` is the gateway's default `identity.Resolver` (see invariant 12 below for the opt-out). It checks `credentials.Store.Verify` (which itself checks `Credential.Effective`) and then, independently, `policy.Client.IsKilled`, both before returning anything to `handleToolCall`, and `handleToolCall` calls the resolver before it ever calls `policy.Check`.

**Tested:** `cmd/gateway/authn_test.go`: eleven unit tests against `credentialResolver.Resolve` directly, covering every failure mode listed above plus the two fail-closed cases (the credential store or the kill check itself failing, which must return a real error, not an unresolved identity, see invariant 12), and integration tests at the `handleToolCall` level, the most direct being `TestHandleToolCall_FakeAgentRefAloneNoLongerAuthenticates`, which asserts a bare `X-Agent-Ref` header gets 401 and that `policy.Check` was called zero times, the regression test for the exact vulnerability this invariant closes. Extended in this pass with `TestHandleToolCall_RotatedAwayCredentialCannotReplay`, `TestHandleToolCall_ExpiredCredentialCannotAuthenticate`, `TestHandleToolCall_DisabledCredentialCannotAuthenticate`, and `TestHandleToolCall_XAgentRefHeaderIsIgnoredWhenAValidCredentialIsAlsoPresent` (a valid credential for one agent plus a spoofed `X-Agent-Ref` for another still resolves and authorizes against the credential's real agent, not the header), all exercised through the real `handleToolCall` path rather than the store alone, a wiring mistake in how the gateway builds its resolver is a different failure mode a store-level test can't catch. `cmd/gateway/concurrency_test.go` covers the same properties under contention: `TestHandleToolCall_ConcurrentRequestsDuringRevoke_NoRequestSucceedsAfterRevokeCompletes` and `TestHandleToolCall_ConcurrentRequestsDuringRotation_OldCredentialNeverSucceedsAfterRotationCompletes` fire fifty concurrent requests against a real `Revoke`/`Rotate` call and assert only that no request succeeds once the store call has actually returned, and `TestHandleToolCall_RestoreDoesNotReviveACredentialThatWasRevokedByTheKillItRestoresFrom` confirms `Restore` clearing an agent's kill sentinel does not resurrect a credential that kill had already cascaded into revoking.

**Status:** Holds, for the gateway's default configuration. Does not hold when an operator sets `NIA_GATEWAY_INSECURE_HEADER_AUTH=1`, which is the point, a named, logged, local-dev-only escape hatch, not a silent gap, see docs/ARCHITECTURE.md's "Credential-backed authentication and state convergence". Covers `cmd/gateway` only, see invariant 13 below for the separate, differently-shaped control plane authentication.

* * *

### 12. Authentication infrastructure failures fail closed, never open

If the credential store or the policy client cannot answer whether a presented credential is valid, that is not the same outcome as the credential being invalid, and must not be treated as either.

**Enforced:** `identity.Resolver.Resolve` returning `(nil, nil)` means "no identity, and that's not an error," the gateway turns it into 401. Returning a non-nil error means "the question couldn't be answered," the gateway turns it into 500. `credentialResolver` keeps these separate deliberately: `credentials.ErrInvalidCredential` from `Verify` collapses to `(nil, nil)`, any other error from `Verify` or from `policy.Client.IsKilled` propagates as a real error.

**Tested:** `cmd/gateway/authn_test.go`'s `TestCredentialResolver_StoreFailureFailsClosedNotUnresolved` and `TestCredentialResolver_KillCheckFailureFailsClosed`, both using a failing test double and asserting the resolver returns a non-nil error, not a nil identity with no error.

**Status:** Holds.

* * *

### 13. When operator authentication is configured, the audit trail records the authenticated operator, never a claimed one

`cmd/api` writes an `operator`, `revoked_by`, `disabled_by`, `enabled_by`, or `rotated_by` value into every audit event its handlers produce. When `NIA_OPERATOR_TOKENS_PATH` is set, that value must come from the caller's authenticated token, not from the request body, regardless of what the body claims.

**Enforced:** `cmd/api/opauth.go`'s `operatorAuthMiddleware` authenticates every request except `GET /healthz` and `GET /metrics` against `opauth.Store.Verify` and stores the resulting operator name on the request context. `resolveOperator(ctx, claimed string)` prefers that context value over `claimed` whenever it's present; every handler that writes an operator-bearing audit event calls `resolveOperator` first rather than using the request body's field directly. `opauth.FromEnvEnforced` is what makes that the default rather than an option: an unset `NIA_OPERATOR_TOKENS_PATH` is now a startup failure, and the only way `server.opStore` ends up nil is an explicit `NIA_ALLOW_UNAUTHENTICATED=1`, which `main` logs loudly. In that one case the middleware never runs and `resolveOperator` falls through to `claimed` unchanged.

**Tested:** `cmd/api/opauth_test.go`'s `TestHandleKill_AuthenticatedOperatorOverridesTheClaimedOneInTheAuditTrail` authenticates as a token belonging to `bogdan`, sends a kill request whose body claims `"operator":"someone-else-entirely"`, and asserts the resulting audit event's `Operator` field is `bogdan`. `TestRoutes_OpauthConfigured_MissingAuthorizationHeaderIsRejected`, `TestRoutes_OpauthConfigured_WrongSchemeIsRejected`, `TestRoutes_OpauthConfigured_InvalidTokenIsRejected`, and `TestRoutes_OpauthConfigured_ValidTokenIsAccepted` cover the middleware's own accept/reject behavior; `TestRoutes_OpauthConfigured_StoreFailureFailsClosedNot401` covers the fail-closed case, a token store outage returns 500, not 401, the same distinction invariant 12 draws for the gateway; `TestRoutes_OpauthConfigured_HealthAndMetricsStayReachableWithoutAToken` and `TestRoutes_NoOpauthConfigured_RequestsWorkWithNoAuthorizationHeader` cover the two carve-outs. Also verified against a real running `nia-api` process, driven with real `curl` and `niactl` requests including a kill with a spoofed `operator` field, the audit trail read back afterward showed the authenticated name.

**Status:** Holds unless a deployment sets `NIA_ALLOW_UNAUTHENTICATED=1`, which is now the only way to run `cmd/api` open. This used to read the other way round, the invariant held only when an operator remembered to set `NIA_OPERATOR_TOKENS_PATH`, and the shipped `deployments/docker-compose.yml` did not set it, so the reference stack ran with every operator field trusted at face value. Inverting the default is what closed that; `deployments/docker-compose.yml` now mounts a tokens file into both services. See "What this document does not cover" below for what opauth still doesn't close even when configured, per-operator scoping in particular.

* * *

### 14. A denied or unauthenticated tool call never reaches the downstream tool, regardless of why it was denied

When `NIA_GATEWAY_DOWNSTREAM_URL` is configured, `handleToolCall` must not call `g.forwarder.Forward` unless identity resolution, credential state, kill state, tool authorization, and resource authorization have all already succeeded. There is no alternate route into a downstream tool that skips any of those gates.

**Enforced:** By construction, not by a runtime check: `cmd/gateway/main.go`'s `handleToolCall` calls `g.forwarder.Forward` exactly once, at the end of the function, after every `return` on a resolve error, an unresolved identity, an unknown tool, a tool lookup error, a policy check error, a tool-level denial, a resource-level check error, and a resource-level denial. `handleToolCall` is the only handler in this codebase that ever calls `Forward`, there is no second HTTP route, no internal helper, and no code path that reaches a `Forwarder` any other way.

**Tested:** `cmd/gateway/forward_integration_test.go`'s `TestForwarding_KilledAgent_DeniedBeforeDownstreamIsEverContacted`, `TestForwarding_RevokedCredential_DeniedBeforeDownstreamIsEverContacted`, and `TestForwarding_ToolDenied_DeniedBeforeDownstreamIsEverContacted` each wire a real `HTTPForwarder` against a real `httptest.Server` and assert its own request counter stays at zero for a killed agent, a revoked credential, and a denied tool grant respectively, the request never left the process, not just that the HTTP status the caller saw looked like a denial. Also verified against a real running stack, not only the test suite: a real standalone downstream server logging every request it received to a file, a real credentialed call reaching it once, then killing that agent and retrying the same credential, the downstream's request log unchanged afterward.

**Status:** Holds, for every denial path that existed at the time this invariant was written. A denial path added later that doesn't return before reaching the forwarding step at the bottom of `handleToolCall` would silently violate this invariant, there is no structural guard, such as a required capability token threaded through the resolved identity, that would catch that mistake at compile time or make it fail loudly at runtime, this is a discipline invariant, not a proven-by-type-system one, worth stating honestly rather than implying stronger than it is.

* * *

### 15. A chained audit event's recorded hash always matches a hash independently recomputed from its own stored data, and always chains from the immediately preceding event's recorded hash

For every event a `Chained` store returns with a non-empty `Hash`: `Hash` must equal `chainHash(Event, PrevHash)` recomputed fresh from the stored `Event` fields and the stored `PrevHash`, and `PrevHash` must equal the immediately preceding chained event's `Hash` (or `GenesisHash`, for the first event in a chain that provably starts at its own beginning). This is the invariant `internal/audit.Verify` exists to check, stated here as its own numbered claim because it's a security property, not just a function description.

**Enforced:** By construction at write time (`InMemorySink.Append` and `PostgresSink.Append` both compute `Hash` from the event and the previous hash before storing either), and independently re-provable at any later time by `Verify`, which recomputes from stored data alone and never trusts what the writing process claimed, see `internal/audit/chain.go`'s own doc comment for why that distinction matters: this invariant would catch a bug in `Append` itself exactly as readily as a deliberate tamper, both look identical, a hash that doesn't match its data.

**Tested:** `internal/audit/chain_test.go`'s `TestVerify_ValidChain_OK` and `TestVerify_FirstEventMustChainFromGenesis` prove the invariant holds for a correctly written chain and that the genesis case is enforced, not assumed. `TestVerify_DetectsModifiedEvent`, `TestVerify_DetectsDeletedEvent`, `TestVerify_DetectsInsertedEvent`, and `TestVerify_DetectsReorderedEvents` each construct a specific violation and confirm `Verify` catches it. `internal/audit/postgres_sink_live_test.go` reruns the same five proofs, an untampered chain plus all four tampering shapes, with real `UPDATE`/`DELETE`/`INSERT` SQL against a real Postgres table rather than a simulated struct mutation, the strongest form of proof this repository's own verification standard asks for.

**Status:** Holds for every event with a non-empty `Hash`. Events written before hash chaining was enabled on a given store (`Hash == ""`) are explicitly outside this invariant's scope, `Verify` reports them as `Skipped`, not as satisfying or violating it, there was never a hash computed for them to check. Two holes in that scoping are closed as of this pass, both of which previously let a tamper come back `OK: true`. An empty `Hash` is only legitimate as a prefix of the chain, chaining is switched on once and never off, so a blanked hash on a row that follows a hashed row is now a break rather than a skip; and `Verify` compares the last event's hash against `Chain.Tip`, the store's separately recorded chain head (`audit_chain_state.last_hash` for `PostgresSink`), which is the only thing that catches a truncation, deleting the newest rows leaves everything that remains perfectly self-consistent. See invariant 19 below. This invariant is about internal consistency of the chain as stored, it says nothing about whether the entire chain, hashes included, was consistently rewritten by someone with full write access to the store, see docs/ARCHITECTURE.md's "Tamper-evident audit" section for that boundary stated in full.

* * *

### 16. An agent's cumulative risk total, and the kill/revoke decisions made from it, are the same across every gateway process sharing the same risk store

Two gateway processes, `monitoring.RiskStoreFromEnv`-constructed against the same `NIA_RISK_DATABASE_URL`, must observe the same running risk total for a given agent regardless of which process handled which call, and a kill or revoke threshold crossed on one process's own `Observe` call must be enforced by the other on its very next request, with no cross-process call between the two beyond the shared store itself.

**Enforced:** `PostgresRiskStore.Accumulate` (`internal/monitoring/postgres_risk_store.go`) is a single UPSERT statement, `INSERT ... ON CONFLICT (agent_ref) DO UPDATE SET cumulative = risk_state.cumulative + EXCLUDED.cumulative ... RETURNING cumulative`, not a read-then-write pair; Postgres's own row-level locking during the `UPDATE` half serializes two concurrent callers for the same `agent_ref`, whether they're goroutines in one process or two different processes entirely, there is no window where both read the same starting value and one update is lost. The kill/revoke decision itself doesn't need a separate invariant here, it's the same `Monitor.Observe` logic invariant 5 already covers, running against whichever total `Accumulate` just returned; what's new is only that the total itself is no longer process-local when `NIA_RISK_DATABASE_URL` is set, see `risk_store.go`'s own doc comment for why a process-local total was a real distributed bypass, not a cosmetic gap.

**Tested:** `internal/monitoring/postgres_risk_store_live_test.go`'s `TestPostgresRiskStore_Live_ConcurrentAccumulateAcrossTwoStoreHandles` opens two independent `*PostgresRiskStore` values, standing in for two real gateway processes rather than sharing a Go pointer, and races 100 concurrent `Accumulate(1)` calls for the same agent split evenly across both, reading the result back through a third, uninvolved connection, confirming no update was lost. `cmd/gateway/distributed_test.go`'s `TestDistributed_RiskAccumulatesAcrossTwoGatewayInstancesSharingARiskStore` and `TestDistributed_KillPerformedThroughOneGatewayInstanceIsEnforcedByTheOther` prove the same property one layer up, through two independent `*gateway` values and real `handleToolCall` requests, including the kill-performed-through-one-instance-enforced-by-the-other case directly. Also verified against real infrastructure end to end, not only these tests: two real `nia-gateway` processes on different ports sharing one real Postgres database and one real Tessera instance, risk-generating calls split across both, a kill triggered by the second process's own `Observe` call, and the first process, which never called `Kill` itself, denying the agent's next request with a real 401.

**Status:** Holds when `NIA_RISK_DATABASE_URL` is set. Unset, the default, `InMemoryRiskStore` is process-local by design, same as it was before this invariant existed, and this invariant does not apply, a deployment running more than one `cmd/gateway` replica with monitoring configured but no shared risk store gets the fragmented, replica-local risk view `risk_store.go`'s own doc comment describes, stated here rather than left to be discovered the way the gap itself originally was. See docs/ARCHITECTURE.md's "Distributed state" section for the full review of which other state stores this pass did and didn't extend the same way.

* * *

### 17. A credential's secret digest is never present in any API response

`credentials.Credential.SecretHash` must never appear, by field name or by value, in the JSON body of any `cmd/api` response, including the one-time issuance and rotation responses that legitimately carry the plaintext secret itself.

**Enforced:** `SecretHash string` carries a `json:"-"` struct tag (`internal/credentials/credentials.go`), the same mechanism `encoding/json` uses everywhere else in Go to exclude a field from marshaling, applied once at the type definition rather than needing every handler that returns a `Credential` to remember to strip it individually. Nothing inside `internal/credentials` reads `SecretHash` through JSON either, every `Store` implementation compares against the struct field or the database column directly, so this costs nothing internally.

**Tested:** `internal/credentials/credentials_test.go`'s `TestCredential_JSONNeverCarriesTheSecretHash` marshals a `Credential` with a known digest and asserts neither the field name nor the digest value appears in the output. `cmd/api/credentials_test.go`'s `TestCredentialResponses_NeverCarryTheSecretHash` checks the same thing end to end through the real issue, rotate, and list handlers, not just the type in isolation. Also confirmed against a real running `nia-api`: before the `json:"-"` tag was added, `niactl credential issue`'s own response body carried a `SecretHash` field in plain sight, confirmed by actually issuing a credential and reading the raw JSON back, not by inspection alone; the same request afterward no longer does.

**Status:** Holds. This was never the same class of exposure as leaking the plaintext secret would have been, a SHA-256 digest isn't reversible to the value it was computed from, but the security hardening directive names it directly, "credential hashes/digests must not be exposed through APIs or logs," and it's a real, previously live surface, not a hypothetical one, closed here rather than argued away as low severity.

* * *

### 18. The identity graph never gates an authorization decision, and a node's presence in a reachability result is never proof it's currently granted

`internal/graph`'s `Reachable`/`Neighbors` describe discovered relationships, historical and append-only. Nothing in this codebase makes an authorization or authentication decision by consulting the graph, and a `grants` edge surviving in the graph after the underlying grant was deleted is expected behavior, not a bug. `internal/policy.Check`/`ListGrants` is the sole source of truth for what's authorized right now.

**Enforced:** `internal/graph.Graph` has no edge-removal method, by design, see that package's doc comment, so there is no code path that could accidentally start relying on the graph shrinking to match current authorization. `handleDeleteGrants` (`cmd/api/main.go`) calls `s.pol.DeleteGrants` only, it never touches `s.graph`. No handler in `cmd/gateway` or `cmd/api` reads `graph.Graph` before making an allow/deny decision, the only two places `s.graph` is read are `handleGraphNeighbors` and `handleGraphReachable`/`handleBlastRadius`, both read-only inspection endpoints whose own doc comments now state this boundary directly.

**Tested:** `cmd/api/graph_test.go`'s `TestGraphEdgeSurvivesGrantDeletion_ButPolicyCheckReflectsCurrentTruth` writes a grant, confirms `policy.Check` allows it, deletes the grant, confirms `policy.Check` now denies it, and confirms the `grants` edge is still present in a `neighbors` query, both halves in one test so neither claim is checked in isolation from the other.

**Status:** Holds, by construction rather than by a check that could be bypassed, there is no `RemoveEdge` to accidentally call. The tradeoff this invariant names directly: an operator or an automated consumer reading `GET /graph/{id}/reachable` or `GET /graph/{id}/blast-radius` as a live permission list would draw a wrong conclusion, this is why both endpoints' doc comments and docs/ARCHITECTURE.md's "The identity graph" section say so explicitly rather than leaving it to be inferred.

* * *

### 19. Every gateway endpoint that returns another agent's security state requires an authenticated operator

`GET /incidents`, `GET /incidents/{id}`, and `GET /risk/{ref}` on `cmd/gateway` return per-agent security state: an agent's cumulative risk total, the thresholds it is being judged against, and the full signal breakdown behind every containment decision made about it. None of them may be served to an unauthenticated caller.

**Enforced:** `cmd/gateway/main.go`'s `routes()` wraps each of the three in `g.operatorOnly`, which applies `opauth.Middleware` against the same `opauth.Store` and the same `NIA_OPERATOR_TOKENS_PATH` file `cmd/api` uses. `POST /tools/{tool}/call` is deliberately not wrapped, an agent authenticates to that path with its own credential (invariant 11), never an operator token, and the two surfaces stay separate. `GET /healthz` and `GET /metrics` are exempt for the same reason they are in `cmd/api`.

**Tested:** `cmd/gateway/opauth_test.go` covers all three paths against a missing header, an unknown token, and a non-Bearer scheme (401 each), and against a valid token (reaches the handler). `TestRoutes_ToolCallPathIsNotGatedOnAnOperatorToken` proves the tool-call path still authenticates the way invariant 11 describes rather than inheriting operator auth, and `TestRoutes_HealthAndMetricsStayReachableWithoutAToken` covers the carve-outs. Also verified against a real running `nia-gateway` binary driven with `curl`: `GET /risk/agent:x` and `GET /incidents` returned 401 with no header, `GET /incidents` returned 200 with a valid token, and an uncredentialed `POST /tools/invoice.read/call` returned its own `could not resolve caller identity` 401, not the operator-auth one, proof the two paths reject for different reasons.

**Status:** Holds unless a deployment sets `NIA_ALLOW_UNAUTHENTICATED=1`, the same single escape hatch invariant 13 names. Before this pass these three endpoints had no authentication of any kind while the tool-call path beside them demanded a verified credential, and that asymmetry was the actual defect. This is authentication, not authorization: any valid operator token can read any agent's risk state, the same scoping gap invariant 13 has.

* * *

### 20. A chain that has been truncated, or whose hashes have been cleared, never verifies as OK

Deleting the newest events from an audit store, or blanking the `hash` and `prev_hash` columns on a suffix of rows, must be reported as a break. Neither is detectable by checking events against each other: a truncated chain's surviving events still link up perfectly, and a blanked row is indistinguishable from a legitimate pre-chaining row by its own content.

**Enforced:** Two rules in `internal/audit.Verify`, both added in this pass. An event with an empty `Hash` that follows an event with a non-empty one is a break, not a skip, because chaining is enabled once per store and never disabled. And `Chain.Tip`, which `PostgresSink` reads from `audit_chain_state.last_hash`, a different table from the events, must equal the last checked event's hash; when no hashed event remains, the tip must still be `GenesisHash`.

**Tested:** `internal/audit/chain_test.go`'s `TestVerify_ClearedHashAfterAHashedEventIsABreak`, `TestVerify_TruncatedChainIsCaughtByTheTip`, and `TestVerify_EveryHashClearedIsCaughtByTheTip`, with `TestVerify_LegacyOnlyTableWithGenesisTipIsOK` and `TestVerify_UntamperedInMemoryChainMatchesItsTip` as the two negative controls that keep the new rules from trivially flagging legitimate states. `internal/audit/postgres_sink_live_test.go`'s `TestPostgresSink_ChainLive_DetectsTruncatedChain` and `TestPostgresSink_ChainLive_DetectsClearedHashColumn` repeat both against a real Postgres table with real `DELETE` and `UPDATE` SQL, run against a real Postgres 16 container.

**Status:** Holds for `PostgresSink`. For `InMemorySink` the tip lives in the same struct as the events, so it catches bugs and careless tampering but not an attacker who already has the process's memory, stated in `Chain.Tip`'s own doc comment rather than implied equivalent. This does not change invariant 15's underlying boundary: an attacker who rewrites the events, their hashes, *and* the chain-state row consistently still defeats the whole scheme, which is what an external anchor would be for, and there still isn't one.

* * *

### What this document does not cover

Multi-replica correctness is no longer a single unproven claim, it splits by which state a decision actually depends on, see docs/ARCHITECTURE.md's "Distributed state" section for the full table. Kill state, credential state, policy state, the audit trail, and, as of invariant 16 above, risk enforcement state are all genuinely safe to share across `cmd/api`/`cmd/gateway` replicas when their respective `NIA_*_DATABASE_URL` (or `NIA_TESSERA_BASE_URL`) variables are set, and this pass verified that against real infrastructure, not just tests, see docs/THREAT_MODEL.md's rewritten threat 11. What's still genuinely process-local and unproven for the multi-replica case: `internal/incident`'s structured records and `internal/registry.InMemoryAgentRegistry`'s cached metadata, neither has a `PostgresX` counterpart yet, and the identity graph, which was never meant to be live authorization state in the first place, and whose historical/append-only model, chosen and tested this pass, means it wouldn't matter for an authorization decision even if it were replicated, see invariant 18 above and the identity graph section above. None of the three gate a decision the way the invariants above do, `GET /agents/{ref}` in particular already live-queries the shared kill state rather than trusting its own cache, so this is a completeness and investigability gap, not an authorization bypass, stated here rather than left to be discovered running a second replica. `internal/opauth`, invariant 13 above, authenticates a caller to `cmd/api` and makes the audit trail's operator field trustworthy when it's configured, but it is not authorization: any valid token can call every endpoint, there is no per-operator scoping or RBAC, an authenticated operator who shouldn't be allowed to kill agents can still kill agents. It also has no live rotation or revocation, changing who holds a valid token means editing the token file and restarting the process, there's no equivalent of `credentials.Store.Revoke` for operator tokens. It is no longer opt-in, which was the single largest gap this document used to carry: both binaries now refuse to start without `NIA_OPERATOR_TOKENS_PATH` unless `NIA_ALLOW_UNAUTHENTICATED=1` is set deliberately, see invariants 13 and 19. The scoping gap above is what remains. Downstream forwarding, invariant 14 above, is also opt-in, and even configured it inspects a response for a narrow, named set of conditions, not full content, a downstream tool that returns a plausible-looking but poisoned 200 raises none of `inspectAndAuditDownstream`'s checks, see docs/THREAT_MODEL.md's threat 6. Invariant 15's hash chain is tamper evidence, not tamper prevention: an attacker who correctly rewrites the entire suffix of the chain after their tamper, or who replaces the whole table wholesale, defeats it, that boundary is stated directly in `internal/audit/chain.go`'s own doc comment rather than left implicit, and nothing here calls `Verify` automatically, it's an on-demand operation (`GET /audit/verify`, `niactl audit verify`), not continuous monitoring or an alert. Bearer credential replay within a still-valid window, invariant 17 is about the digest never leaking, not about the live secret being single-use, is also not covered anywhere in this codebase, see docs/THREAT_MODEL.md's threat 1 for that boundary stated directly: `<id>.<secret>` has no nonce or freshness check, a captured valid credential is reusable for its full remaining lifetime. All of these gaps are named directly rather than implied covered by their invariant's presence in this list.
