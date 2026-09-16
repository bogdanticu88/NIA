# NIA security invariants

An invariant here is a specific, checkable claim about what NIA guarantees, stated precisely enough that a test can either confirm it holds or prove it doesn't. This is different from docs/THREAT_MODEL.md, which asks "does this threat get handled" across five broad categories; this document asks "what exactly does NIA promise, and where's the test." Several invariants below are fail-open by design, stated that way on purpose rather than treated as bugs, the distinction that matters is between a fail-open posture that was decided and tested, and one that was never decided at all, silently wrong. Two items that used to be the second kind got fixed in this pass specifically so they could move to the first, see invariants 6 and 7 below.

* * *

### 1. Kill denies every subsequent check, unconditionally

Once an agent is killed, every `policy.Check` call for that agent returns `false`, regardless of what grants exist for it, until it's explicitly restored.

**Enforced:** `InMemoryClient.Check` and Tessera's `CheckAsync` both consult the kill sentinel before anything else. `InMemoryClient.Kill` sets the sentinel and clears the agent's grants in the same call, sentinel-first, so a concurrent grant write can't land after a kill and resurrect access.

**Tested:** `internal/policy/policy_test.go`'s `TestKillDeniesEvenPriorGrants` (a killed agent with standing grants still gets denied) and `TestReconcileNeverResurrectsAKill` (a reconcile call after a kill doesn't restore access). Confirmed a second way, against a real backend, not just the in-memory reference: registered against a live Tessera-plus-OpenFGA stack, checked as allowed, killed, checked again as denied, real tuples deleted, see docs/ARCHITECTURE.md's "Integration plan for Tessera" section.

**Status:** Holds, in both the in-memory reference and the real Tessera integration, single-instance. Not verified across concurrent Tessera/Tessera or `cmd/api`/`cmd/api` replicas, see invariant 10.

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

**Enforced:** `Monitor.Observe`'s `cumulative[agentRef]` map, mutex-protected, only cleared inside the `ActionKill` branch.

**Tested:** `internal/monitoring/monitoring_test.go`'s `TestObserve_RiskAccumulatesAcrossCalls_CrossesThresholdOnTheThirdCall`, `TestObserve_RiskAccumulationIsPerAgent` (agent B's calls don't affect agent A's total), `TestObserve_KillResetsCumulativeRisk`, `TestObserve_RevokeDoesNotResetCumulativeRisk`, and `TestObserve_RiskAccumulationIsRaceSafe` (fifty concurrent `Observe` calls for one agent, checked afterward that the total lost no updates, `go test -race` run against it).

**Status:** Holds, including under concurrent calls to the same running process. Two separate gateway replicas would each keep their own total, unrelated to each other, see invariant 10, this invariant is about one process's own bookkeeping being race-safe, not about multiple processes agreeing on one total.

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

### What this document does not cover

Multi-replica correctness, more than one `cmd/api`, `cmd/gateway`, or `Tessera.Service` instance against the same backing store, is not a stated invariant here because it isn't proven in either direction, see docs/THREAT_MODEL.md's threat 11 and docs/ARCHITECTURE.md's "Integration plan for Tessera" section for what's known and what isn't. Identity resolution at the gateway, whether the caller actually is who it claims to be, is also not listed as an invariant here because there currently isn't one to state, `headerResolver` trusts a header outright, see docs/THREAT_MODEL.md's threats 1 and 2. Both are named directly rather than implied covered by their absence from this list.
