// cmd/api is the NIA control-plane API: agent registration, NHI
// inventory, credential issuance, tool registration, permission
// grants (proxied to the policy client), audit query, and kill/restore.
// This is not the hot path; the gateway (cmd/gateway) is. This service
// manages the state the gateway's live checks read.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bogdanticu88/nia/internal/audit"
	"github.com/bogdanticu88/nia/internal/credentials"
	"github.com/bogdanticu88/nia/internal/graph"
	"github.com/bogdanticu88/nia/internal/identity"
	"github.com/bogdanticu88/nia/internal/metrics"
	"github.com/bogdanticu88/nia/internal/opauth"
	"github.com/bogdanticu88/nia/internal/policy"
	"github.com/bogdanticu88/nia/internal/ratelimit"
	"github.com/bogdanticu88/nia/internal/registry"
	"github.com/bogdanticu88/nia/internal/registry/tools"
	"github.com/bogdanticu88/nia/internal/sensitivity"
	niahttp "github.com/bogdanticu88/nia/internal/transport/http"
)

// server wires every control-plane dependency together. Every field is
// an interface; main() below is the only place that decides which
// implementation (in-memory reference vs. a real Postgres/Tessera-backed
// one) satisfies it. Swapping the policy client for a real Tessera HTTP
// adapter, once it exists, touches only this constructor.
type server struct {
	agents    registry.AgentRegistry
	toolCat   tools.Catalog
	creds     credentials.Store
	pol       policy.Client
	auditLog  audit.Store
	graph     graph.Graph
	sensitive sensitivity.Classifier // optional, nil means blast-radius severity never sees anything above public, see handleBlastRadius
	opStore   opauth.Store           // optional, nil means operator authentication is off, see opauth.go and opauth.FromEnv's own doc comment
	// checkpointer is nil when NIA_AUDIT_CHECKPOINT_KEY is unset, which
	// means the audit trail is tamper evident but unanchored: a rewrite
	// that recomputes every hash consistently verifies clean. See
	// internal/audit/checkpoint.go.
	checkpointer    *audit.Checkpointer
	checkpointStore audit.CheckpointStore
	// limiter bounds requests per client address, applied in front of
	// everything including authentication, see routes(). A flood of
	// unauthenticated requests is the case it exists for: each one costs
	// a token-store lookup and none of them is audited, there is no
	// resolved operator to attribute an event to.
	limiter        *ratelimit.Limiter
	trustForwarded bool
	metrics        *serverMetrics
	metricsReg     *metrics.Registry // handleFunc target for GET /metrics, metrics is the typed counters callers actually use
}

// serverMetrics is every counter and gauge cmd/api exposes over GET
// /metrics, named to match what each handler already logs to
// internal/audit, so a metric and an audit action describe the same
// event two different ways rather than inventing a second vocabulary.
// Registration and tool-registration get a "duplicate" result bucket of
// their own rather than folding it into "error", it's the specific,
// common, non-error case invariant 7 (see docs/SECURITY_INVARIANTS.md)
// exists to keep distinct from an actual backend failure; everything
// else uses a plain success/error split. audit_write_failures and
// graph_write_failures exist specifically to make the fail-open
// postures docs/SECURITY_INVARIANTS.md invariants 8 and 9 describe
// observable, previously nothing surfaced them beyond a log line.
type serverMetrics struct {
	registrations      *metrics.Counter // result: created|duplicate|error
	toolRegistrations  *metrics.Counter // result: created|duplicate|error
	credentialsIssued  *metrics.Counter // result: success|error
	credentialsRevoked *metrics.Counter // result: success|error
	grantsWritten      *metrics.Counter // result: success|killed|error
	grantsDeleted      *metrics.Counter // result: success|error
	kills              *metrics.Counter // result: success|error
	auditWriteFailures *metrics.Counter // no labels
	graphWriteFailures *metrics.Counter // op: add_node|add_edge
	rateLimited        *metrics.Counter // no labels, one per request refused with 429
}

func newServerMetrics(reg *metrics.Registry, s *server) *serverMetrics {
	m := &serverMetrics{
		registrations:      reg.NewCounter("nia_agent_registrations_total", "agent registration attempts by result", "result"),
		toolRegistrations:  reg.NewCounter("nia_tool_registrations_total", "tool registration attempts by result", "result"),
		credentialsIssued:  reg.NewCounter("nia_credentials_issued_total", "credential issuance attempts by result", "result"),
		credentialsRevoked: reg.NewCounter("nia_credentials_revoked_total", "credential revocation attempts by result", "result"),
		grantsWritten:      reg.NewCounter("nia_grants_written_total", "grant write attempts by result", "result"),
		grantsDeleted:      reg.NewCounter("nia_grants_deleted_total", "grant delete attempts by result", "result"),
		kills:              reg.NewCounter("nia_kills_total", "kill switch invocations by result", "result"),
		auditWriteFailures: reg.NewCounter("nia_audit_write_failures_total", "audit trail append failures, fail-open by design, see docs/SECURITY_INVARIANTS.md invariant 8"),
		graphWriteFailures: reg.NewCounter("nia_graph_write_failures_total", "identity graph write failures, fail-open by design, see docs/SECURITY_INVARIANTS.md invariant 9", "op"),
		rateLimited:        reg.NewCounter("nia_rate_limited_total", "requests refused with 429 by the per-client rate limiter"),
	}
	reg.NewGaugeFunc("nia_rate_limit_tracked_clients", "client addresses currently holding a rate-limit bucket", func() float64 {
		return float64(s.limiter.Tracked())
	})
	reg.NewGaugeFunc("nia_agents_registered", "agents currently in the registry", func() float64 {
		list, err := s.agents.List(context.Background())
		if err != nil {
			return 0
		}
		return float64(len(list))
	})
	reg.NewGaugeFunc("nia_tools_registered", "tools currently in the catalog", func() float64 {
		list, err := s.toolCat.List(context.Background())
		if err != nil {
			return 0
		}
		return float64(len(list))
	})
	return m
}

// newServer wires every control-plane dependency. The policy client comes
// from policy.FromEnv: NIA_TESSERA_BASE_URL unset means the in-memory
// reference client, no Tessera required to run this locally, set it and
// the required signing key alongside it and this talks to a real Tessera
// instance instead. See internal/policy/from_env.go for the full env var
// list and internal/policy/tessera_client.go's doc comment for what
// TesseraHTTPClient does and doesn't guarantee relative to the in-memory
// one. The audit store follows the same pattern: audit.FromEnv, unset
// NIA_AUDIT_DATABASE_URL means an in-memory sink private to this
// process, set it (to the same value cmd/gateway is started with) and
// both share one real audit trail instead of two separate in-memory
// ones, see internal/audit/from_env.go.
func newServer(ctx context.Context) (*server, error) {
	// policy.FromEnvWithLocker rather than FromEnv: cmd/api is where
	// grant writes happen, and those are a read-modify-write against
	// Tessera that the client's own per-agent mutex can only serialize
	// within one process. NIA_POLICY_LOCK_DATABASE_URL unset keeps the
	// previous behaviour, which is correct for a single replica.
	pol, sharedGrantLock, err := policy.FromEnvWithLocker(ctx)
	if err != nil {
		return nil, fmt.Errorf("nia-api: %w", err)
	}
	if !sharedGrantLock {
		log.Printf("nia-api: grant writes are serialized within this process only, set NIA_POLICY_LOCK_DATABASE_URL to serialize them across replicas")
	}
	auditLog, err := audit.FromEnv(ctx)
	if err != nil {
		return nil, fmt.Errorf("nia-api: %w", err)
	}
	// Same NIA_SENSITIVITY_RULES_PATH env var cmd/gateway reads, unset
	// means every resource classifies as Public, so a blast-radius query
	// still returns its node counts, it just can't say which reachable
	// data resources are the sensitive or critical ones.
	sensitive, err := sensitivity.FromEnvClassifier()
	if err != nil {
		return nil, fmt.Errorf("nia-api: %w", err)
	}
	// credentials.FromEnv: unset NIA_CREDENTIALS_DATABASE_URL means an
	// in-memory store private to this process, same posture as audit and
	// policy above. Set it (to the same value cmd/gateway is started
	// with) and both processes verify against one real credential store
	// instead of cmd/gateway never being able to see a credential this
	// process issued at all, see internal/credentials/from_env.go.
	creds, err := credentials.FromEnv(ctx)
	if err != nil {
		return nil, fmt.Errorf("nia-api: %w", err)
	}
	// opauth.FromEnvEnforced: NIA_OPERATOR_TOKENS_PATH unset is a
	// startup failure, not a silently open control plane. The only way
	// to get a nil opStore (and so a mux routes() never wraps in
	// operatorAuthMiddleware) is NIA_ALLOW_UNAUTHENTICATED=1, set
	// deliberately. Before this, unset meant open, and the shipped
	// docker-compose.yml didn't set it, so the reference deployment
	// exposed agent registration, grant writes, credential issuance,
	// kill, restore, and the whole audit trail with no authentication
	// at all. See docs/SECURITY_INVARIANTS.md invariant 11.
	opStore, openOnPurpose, err := opauth.FromEnvEnforced()
	if err != nil {
		return nil, fmt.Errorf("nia-api: %w", err)
	}
	if openOnPurpose {
		log.Printf("nia-api: %s=1, this process accepts every request unauthenticated and trusts operator/*_by fields at face value, this must never be set on anything reachable by an untrusted caller", opauth.EnvAllowUnauthenticated)
	}
	rateCfg, err := ratelimit.FromEnv()
	if err != nil {
		return nil, fmt.Errorf("nia-api: %w", err)
	}
	// registry.FromEnv: NIA_REGISTRY_DATABASE_URL unset means the agent
	// inventory is this process's own map, so a second replica returns
	// 404 for an agent this one registered. No authorization decision
	// depends on it (handleGetAgent reads kill state live from the
	// policy client), but an inventory that disagrees with itself is
	// not a property a control plane gets to have.
	// audit.CheckpointerFromEnv: unset key means a nil Checkpointer, and
	// every method on it answers ErrNoCheckpointKey, so the handlers can
	// hold it unconditionally rather than guarding each call.
	checkpointer, err := audit.CheckpointerFromEnv()
	if err != nil {
		return nil, fmt.Errorf("nia-api: %w", err)
	}
	checkpointStore, durableCheckpoints, err := audit.CheckpointStoreFromEnv(ctx)
	if err != nil {
		return nil, fmt.Errorf("nia-api: %w", err)
	}
	switch {
	case !checkpointer.Configured():
		log.Printf("nia-api: NIA_AUDIT_CHECKPOINT_KEY is not set, the audit trail is tamper evident but unanchored, a rewrite that recomputes every hash consistently would verify clean")
	case !durableCheckpoints:
		log.Printf("nia-api: audit checkpoints are signed but kept in memory and will not survive a restart, set NIA_AUDIT_DATABASE_URL to keep them")
	}

	agents, sharedRegistry, err := registry.FromEnv(ctx)
	if err != nil {
		return nil, fmt.Errorf("nia-api: %w", err)
	}
	if !sharedRegistry {
		log.Printf("nia-api: the agent inventory is process-local, set NIA_REGISTRY_DATABASE_URL to share it across replicas")
	}
	s := &server{
		limiter:         rateCfg.PerClient(),
		trustForwarded:  rateCfg.TrustForwardedFor,
		agents:          agents,
		toolCat:         tools.NewInMemoryCatalog(),
		creds:           creds,
		pol:             pol,
		auditLog:        auditLog,
		graph:           graph.NewInMemoryGraph(),
		sensitive:       sensitive,
		opStore:         opStore,
		checkpointer:    checkpointer,
		checkpointStore: checkpointStore,
	}
	reg := metrics.NewRegistry()
	s.metrics = newServerMetrics(reg, s)
	s.metricsReg = reg
	return s, nil
}

func (s *server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	niahttp.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type registerAgentRequest struct {
	Ref          string `json:"ref"`
	DisplayName  string `json:"display_name"`
	Owner        string `json:"owner"`
	BusinessUnit string `json:"business_unit"`
	Purpose      string `json:"purpose"`
}

func (s *server) handleRegisterAgent(w http.ResponseWriter, r *http.Request) {
	var req registerAgentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		niahttp.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Ref == "" {
		niahttp.WriteError(w, http.StatusBadRequest, "ref is required")
		return
	}

	agent := identity.AgentRef{
		Ref:          req.Ref,
		DisplayName:  req.DisplayName,
		Owner:        req.Owner,
		BusinessUnit: req.BusinessUnit,
		Purpose:      req.Purpose,
		Assurance:    identity.AssuranceMedium,
		State:        identity.StateActive,
	}

	ctx := r.Context()
	if err := s.agents.Register(ctx, agent); err != nil {
		// The in-memory registry only ever returns ErrAlreadyRegistered,
		// which made this safe to map straight to 409 without checking,
		// but that stops being true the day this is backed by something
		// real that can fail other ways (a database down, say), and a
		// caller deserves 500, not a false "you already registered
		// this," for that. See docs/SECURITY_INVARIANTS.md.
		if errors.Is(err, registry.ErrAlreadyRegistered) {
			s.metrics.registrations.Inc("duplicate")
			niahttp.WriteError(w, http.StatusConflict, err.Error())
			return
		}
		s.metrics.registrations.Inc("error")
		niahttp.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.metrics.registrations.Inc("created")
	// Push the business unit through to the policy engine. Until
	// policy.Client grew SetBusinessUnit there was no path to do this at
	// all, so an agent registered with a business unit here had it
	// recorded in NIA's own registry and nowhere else, and the Tessera
	// side always read as empty. Same fail-open posture as the graph and
	// audit writes below: registration itself already succeeded, and a
	// failure to propagate an attribute is logged rather than turned
	// into a failed registration the caller would reasonably retry.
	if agent.BusinessUnit != "" {
		if err := s.pol.SetBusinessUnit(ctx, agent.Ref, agent.BusinessUnit); err != nil {
			log.Printf("nia-api: declaring the business unit for %s to the policy engine failed: %v", agent.Ref, err)
		}
	}
	s.graphAddNode(ctx, agent.Ref, graph.NodeAgent)
	s.audit(ctx, audit.Event{
		Action:   "agent.registered",
		AgentRef: agent.Ref,
		Operator: req.Owner,
		At:       time.Now(),
	})
	niahttp.WriteJSON(w, http.StatusCreated, agent)
}

// listKillCheckConcurrency bounds how many live kill-sentinel checks run
// at once. Each one is an HTTP round trip to Tessera when a real policy
// client is configured, so an unbounded fan-out over a large inventory
// would be a self-inflicted load spike against the policy engine, and a
// serial loop would make the endpoint unusably slow for the same
// inventory. Eight is enough to keep the wall time close to a single
// round trip for a realistic agent population without being a burst
// anything would notice.
const listKillCheckConcurrency = 8

func (s *server) handleListAgents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	agents, err := s.agents.List(ctx)
	if err != nil {
		niahttp.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// The registry's State field is a cache, updated by handleKill,
	// handleRestore and handleRegisterAgent. It goes stale for exactly
	// the case that matters most: cmd/gateway's automatic, risk-triggered
	// kills go through internal/policy directly and never touch this
	// process's registry, so an agent that monitoring killed an hour ago
	// still listed here as active.
	//
	// handleGetAgent has always read the live sentinel for one agent.
	// This endpoint did not, so the same control plane gave two
	// different answers about the same agent depending on which way you
	// asked, and the wrong one was the one an operator scanning a list
	// during an incident would see. Both report the same shape now.
	reports := make([]agentReport, len(agents))
	sem := make(chan struct{}, listKillCheckConcurrency)
	var wg sync.WaitGroup
	for i, agent := range agents {
		reports[i] = agentReport{AgentRef: agent, EffectiveState: agent.State}
		wg.Add(1)
		go func(i int, ref string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			killed, err := s.pol.IsKilled(ctx, ref)
			if err != nil {
				// Same posture as handleGetAgent: a failed check leaves
				// KillSentinelChecked false and the cached state showing,
				// rather than guessing in either direction. A caller can
				// tell "this is confirmed live" from "this is what the
				// registry last recorded" by reading that field, which is
				// the whole reason it is on the wire.
				log.Printf("nia-api: live kill-sentinel check failed for %s during list: %v", ref, err)
				return
			}
			reports[i].KillSentinelChecked = true
			if killed {
				reports[i].EffectiveState = identity.StateKilled
			}
		}(i, agent.Ref)
	}
	wg.Wait()

	niahttp.WriteJSON(w, http.StatusOK, reports)
}

// handleGetAgent looks up one agent's identity record. Everything else
// this control plane knows about an agent (grants, credentials, audit
// history, graph reachability) is already its own sub-resource endpoint;
// this is the one piece, the identity record itself, that had no direct
// lookup until niactl agent inspect needed to show it without pulling
// the entire agent list and filtering client side.
// agentReport is what GET /agents/{ref} returns. State is the local
// registry's own cached field, set by handleRegisterAgent, handleKill,
// and handleRestore; it can lag reality when something killed the agent
// through a different process, see docs/ARCHITECTURE.md's "State
// convergence" section for the exact gap this closes: cmd/gateway's
// automatic, risk-triggered kills go through internal/policy directly
// and never touched this registry before this pass. EffectiveState is
// what actually matters operationally: it's State unless a live query
// against s.pol (the same policy client cmd/gateway checks on every
// request, the one genuinely shared source of truth across processes
// when both point at a real Tessera instance rather than each running
// its own in-memory default, see cmd/gateway's own package doc comment)
// says the kill sentinel is set, in which case EffectiveState is forced
// to killed regardless of what the cache says. KillSentinelChecked is
// false when that live query itself failed, so a caller can tell "we
// confirmed this against the real enforcement state" apart from "we're
// only showing you the cache because we couldn't reach the policy
// client," rather than silently falling back to a possibly-stale
// answer and calling it the same thing.
type agentReport struct {
	identity.AgentRef
	EffectiveState      identity.LifecycleState `json:"effective_state"`
	KillSentinelChecked bool                    `json:"kill_sentinel_checked"`
}

func (s *server) handleGetAgent(w http.ResponseWriter, r *http.Request) {
	ref := r.PathValue("ref")
	if ref == "" {
		niahttp.WriteError(w, http.StatusBadRequest, "agent ref is required")
		return
	}
	ctx := r.Context()
	agent, err := s.agents.Get(ctx, ref)
	if err != nil {
		if errors.Is(err, registry.ErrNotFound) {
			niahttp.WriteError(w, http.StatusNotFound, "agent not registered")
			return
		}
		niahttp.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	report := agentReport{AgentRef: agent, EffectiveState: agent.State}
	killed, err := s.pol.IsKilled(ctx, ref)
	if err != nil {
		log.Printf("nia-api: live kill-sentinel check failed for %s: %v", ref, err)
	} else {
		report.KillSentinelChecked = true
		if killed {
			report.EffectiveState = identity.StateKilled
		}
	}
	niahttp.WriteJSON(w, http.StatusOK, report)
}

type killRequest struct {
	AgentRef string `json:"agent_ref"`
	Incident string `json:"incident"`
	Operator string `json:"operator"`
}

func (s *server) handleKill(w http.ResponseWriter, r *http.Request) {
	var req killRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		niahttp.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	ctx := r.Context()
	// operator prefers the authenticated caller (see opauth.go) over
	// whatever the request body claims, when operator auth is
	// configured at all; unconfigured, this is exactly req.Operator,
	// unchanged from before opauth existed.
	operator := resolveOperator(ctx, req.Operator)
	result, err := s.pol.Kill(ctx, req.AgentRef, req.Incident, operator)
	if err != nil {
		s.metrics.kills.Inc("error")
		niahttp.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.metrics.kills.Inc("success")
	// The kill itself already succeeded, that's what actually matters,
	// so a failure here is logged rather than turned into a failed
	// response, same fail-open posture as s.audit and the graph
	// auto-population helpers, see docs/SECURITY_INVARIANTS.md. Silently
	// discarding this error used to mean the registry could report an
	// agent as active that Tessera/OpenFGA had actually killed, with
	// nothing to show for it, not even a log line. This is a local cache
	// update, not the source of truth, see handleGetAgent, which reads
	// the live kill sentinel from s.pol on every call rather than
	// trusting this field alone, that's what actually closes the state
	// convergence gap docs/ARCHITECTURE.md describes, this SetState call
	// just keeps the cache from being needlessly stale in the meantime.
	if err := s.agents.SetState(ctx, req.AgentRef, identity.StateKilled); err != nil {
		log.Printf("nia-api: registry state update to killed failed for %s: %v", req.AgentRef, err)
	}
	// Convergence means credential state = REVOKED too, not just the
	// policy sentinel, see docs/ARCHITECTURE.md's "State convergence"
	// section: a killed agent's old credentials used to sit around
	// reporting Active forever even though every authorization check
	// already denied them. Same fail-open posture as everything else in
	// this handler, a revoke failure here doesn't undo or block the
	// kill that already happened.
	revoked := s.revokeAllCredentials(ctx, req.AgentRef, operator, "agent killed: "+req.Incident)
	s.audit(ctx, audit.Event{
		Action:   "agent.killed",
		AgentRef: req.AgentRef,
		Operator: operator,
		Incident: req.Incident,
		Detail:   fmt.Sprintf("revoked %d credential(s)", revoked),
		At:       time.Now(),
	})
	niahttp.WriteJSON(w, http.StatusOK, result)
}

// revokeAllCredentials retires every currently-active credential for
// agentRef. Used by both handleKill (a manual, operator-initiated kill)
// and, via the equivalent helper in internal/monitoring, an automatic
// risk-triggered kill, so both paths converge on the same "kill also
// means credentials are gone" guarantee rather than one of them being a
// partial containment action. Best-effort: a single credential's
// revoke failing is logged and the loop continues, one bad row
// shouldn't stop the rest from being retired.
func (s *server) revokeAllCredentials(ctx context.Context, agentRef, revokedBy, reason string) int {
	creds, err := s.creds.ListForAgent(ctx, agentRef)
	if err != nil {
		log.Printf("nia-api: listing credentials for %s during kill failed: %v", agentRef, err)
		return 0
	}
	revoked := 0
	for _, c := range creds {
		if c.Effective(time.Now()) != credentials.StatusActive {
			continue
		}
		if err := s.creds.Revoke(ctx, c.ID, revokedBy, reason); err != nil {
			log.Printf("nia-api: revoking credential %s for %s during kill failed: %v", c.ID, agentRef, err)
			continue
		}
		revoked++
	}
	return revoked
}

type restoreRequest struct {
	AgentRef string `json:"agent_ref"`
	Operator string `json:"operator"`
}

// handleRestore is new: the package doc comment and niactl's own usage
// text both claimed "kill/restore" existed, but no restore endpoint was
// ever wired up, see the audit findings for this pass. internal/policy's
// Restore only clears the kill sentinel, it deliberately does not
// resurrect grants on its own (see Client.Restore's doc comment), so
// this handler doesn't either: an operator who restores an agent must
// separately call handleWriteGrants with the intended grants. It also
// does not un-revoke credentials, revocation is one-way by design (see
// credentials.Store.Revoke), a restored agent needs a freshly issued
// credential, not its old one back.
func (s *server) handleRestore(w http.ResponseWriter, r *http.Request) {
	var req restoreRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		niahttp.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.AgentRef == "" {
		niahttp.WriteError(w, http.StatusBadRequest, "agent_ref is required")
		return
	}
	ctx := r.Context()
	operator := resolveOperator(ctx, req.Operator)
	if operator == "" {
		// The policy client requires an operator now, for the same
		// reason Kill always has: a restore attributed to nobody is a
		// record an incident review cannot use. Rejecting here rather
		// than letting the client error gives the caller a message
		// about their request instead of one about Tessera.
		niahttp.WriteError(w, http.StatusBadRequest, "operator is required, either authenticate with an operator token or set \"operator\" in the request body")
		return
	}
	if err := s.pol.Restore(ctx, req.AgentRef, operator); err != nil {
		niahttp.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.agents.SetState(ctx, req.AgentRef, identity.StateActive); err != nil {
		log.Printf("nia-api: registry state update to active failed for %s: %v", req.AgentRef, err)
	}
	s.audit(ctx, audit.Event{
		Action:   "agent.restored",
		AgentRef: req.AgentRef,
		Operator: operator,
		At:       time.Now(),
	})
	niahttp.WriteJSON(w, http.StatusOK, map[string]string{
		"agent_ref": req.AgentRef,
		"status":    "restored",
		"note":      "kill sentinel cleared; grants and credentials were not restored, write grants and issue a fresh credential separately",
	})
}

type issueCredentialRequest struct {
	Kind       string `json:"kind"`
	TTLSeconds int64  `json:"ttl_seconds"`
	Operator   string `json:"operator"`
}

// handleIssueCredential mints credential metadata for an already
// registered agent. It requires the agent to exist first, issuance
// isn't a backdoor way to create an identity record, registration is
// (see handleRegisterAgent). The credential material itself is never
// generated here, see internal/credentials's package doc for why.
func (s *server) handleIssueCredential(w http.ResponseWriter, r *http.Request) {
	ref := r.PathValue("ref")
	if ref == "" {
		niahttp.WriteError(w, http.StatusBadRequest, "agent ref is required")
		return
	}
	ctx := r.Context()
	if _, err := s.agents.Get(ctx, ref); err != nil {
		niahttp.WriteError(w, http.StatusNotFound, "agent not registered")
		return
	}

	var req issueCredentialRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		niahttp.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	kind := credentials.Kind(req.Kind)
	switch kind {
	case credentials.KindAPIKey, credentials.KindOAuthToken, credentials.KindMTLSCert:
	default:
		niahttp.WriteError(w, http.StatusBadRequest, "kind must be one of api_key, oauth_token, mtls_cert")
		return
	}
	var ttl time.Duration
	if req.TTLSeconds > 0 {
		ttl = time.Duration(req.TTLSeconds) * time.Second
	}

	cred, secret, err := s.creds.Issue(ctx, ref, kind, ttl)
	if err != nil {
		s.metrics.credentialsIssued.Inc("error")
		niahttp.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.metrics.credentialsIssued.Inc("success")
	s.graphAddNode(ctx, cred.ID, graph.NodeCredential)
	s.graphAddEdge(ctx, cred.ID, ref, graph.EdgeBoundTo)
	s.audit(ctx, audit.Event{
		Action:   "credential.issued",
		AgentRef: ref,
		Operator: resolveOperator(ctx, req.Operator),
		Detail:   string(kind) + " " + cred.ID,
		At:       time.Now(),
	})
	niahttp.WriteJSON(w, http.StatusCreated, issuedCredential{Credential: cred, Secret: secret})
}

// issuedCredential is what handleIssueCredential and handleRotateCredential
// return: the credential record plus the one-time plaintext secret the
// agent needs to present at the gateway as "Bearer <id>.<secret>", see
// cmd/gateway/authn.go. This is the only response anywhere in this API
// that ever carries a plaintext secret. GET /agents/{ref}/credentials
// and every other read path return bare Credential values too, but
// credentials.Credential.SecretHash carries a json:"-" tag, so even
// the digest never goes out over any of these responses, not just the
// plaintext, see that field's own doc comment for why.
type issuedCredential struct {
	credentials.Credential
	Secret string `json:"secret"`
}

func (s *server) handleListCredentials(w http.ResponseWriter, r *http.Request) {
	ref := r.PathValue("ref")
	if ref == "" {
		niahttp.WriteError(w, http.StatusBadRequest, "agent ref is required")
		return
	}
	creds, err := s.creds.ListForAgent(r.Context(), ref)
	if err != nil {
		niahttp.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	niahttp.WriteJSON(w, http.StatusOK, creds)
}

type revokeCredentialRequest struct {
	RevokedBy string `json:"revoked_by"`
	Reason    string `json:"reason"`
}

// handleRevokeCredential retires one credential. This is deliberately
// smaller than handleKill: it takes out one key, not the whole agent,
// see internal/credentials's package doc for why the two are kept
// separate rather than folded into one endpoint.
func (s *server) handleRevokeCredential(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		niahttp.WriteError(w, http.StatusBadRequest, "credential id is required")
		return
	}
	var req revokeCredentialRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		niahttp.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	ctx := r.Context()
	operator := resolveOperator(ctx, req.RevokedBy)
	cred, err := s.creds.Get(ctx, id)
	if err != nil {
		if errors.Is(err, credentials.ErrNotFound) {
			niahttp.WriteError(w, http.StatusNotFound, "credential not found")
			return
		}
		niahttp.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.creds.Revoke(ctx, id, operator, req.Reason); err != nil {
		s.metrics.credentialsRevoked.Inc("error")
		niahttp.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.metrics.credentialsRevoked.Inc("success")
	s.audit(ctx, audit.Event{
		Action:   "credential.revoked",
		AgentRef: cred.AgentRef,
		Operator: operator,
		Detail:   req.Reason,
		At:       time.Now(),
	})

	updated, err := s.creds.Get(ctx, id)
	if err != nil {
		niahttp.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	niahttp.WriteJSON(w, http.StatusOK, updated)
}

type disableCredentialRequest struct {
	DisabledBy string `json:"disabled_by"`
	Reason     string `json:"reason"`
}

// handleDisableCredential is the reversible counterpart to
// handleRevokeCredential, see credentials.Store.Disable's own doc
// comment for why the two are kept distinct: an administrative pause,
// not a security decision, and one that Enable can undo.
func (s *server) handleDisableCredential(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		niahttp.WriteError(w, http.StatusBadRequest, "credential id is required")
		return
	}
	var req disableCredentialRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		niahttp.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	ctx := r.Context()
	operator := resolveOperator(ctx, req.DisabledBy)
	cred, err := s.creds.Get(ctx, id)
	if err != nil {
		if errors.Is(err, credentials.ErrNotFound) {
			niahttp.WriteError(w, http.StatusNotFound, "credential not found")
			return
		}
		niahttp.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.creds.Disable(ctx, id, operator, req.Reason); err != nil {
		niahttp.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(ctx, audit.Event{
		Action:   "credential.disabled",
		AgentRef: cred.AgentRef,
		Operator: operator,
		Detail:   req.Reason,
		At:       time.Now(),
	})
	updated, err := s.creds.Get(ctx, id)
	if err != nil {
		niahttp.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	niahttp.WriteJSON(w, http.StatusOK, updated)
}

type enableCredentialRequest struct {
	EnabledBy string `json:"enabled_by"`
}

func (s *server) handleEnableCredential(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		niahttp.WriteError(w, http.StatusBadRequest, "credential id is required")
		return
	}
	var req enableCredentialRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		niahttp.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	ctx := r.Context()
	operator := resolveOperator(ctx, req.EnabledBy)
	cred, err := s.creds.Get(ctx, id)
	if err != nil {
		if errors.Is(err, credentials.ErrNotFound) {
			niahttp.WriteError(w, http.StatusNotFound, "credential not found")
			return
		}
		niahttp.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.creds.Enable(ctx, id, operator); err != nil {
		if errors.Is(err, credentials.ErrInvalidCredential) {
			niahttp.WriteError(w, http.StatusConflict, "credential is revoked, revocation is one-way, issue a new credential instead")
			return
		}
		niahttp.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(ctx, audit.Event{
		Action:   "credential.enabled",
		AgentRef: cred.AgentRef,
		Operator: operator,
		At:       time.Now(),
	})
	updated, err := s.creds.Get(ctx, id)
	if err != nil {
		niahttp.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	niahttp.WriteJSON(w, http.StatusOK, updated)
}

type rotateCredentialRequest struct {
	RotatedBy  string `json:"rotated_by"`
	TTLSeconds int64  `json:"ttl_seconds"`
}

// handleRotateCredential is the fix for "credential rotation must not
// accidentally leave the old credential valid": issuing a replacement
// and revoking the old one used to be two separate API calls an
// operator had to remember to both make, with a window between them
// where a leaked old credential and a fresh new one were both live at
// once. This is one call, backed by credentials.Store.Rotate's atomic
// revoke-then-issue, see that method's own doc comment.
func (s *server) handleRotateCredential(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		niahttp.WriteError(w, http.StatusBadRequest, "credential id is required")
		return
	}
	var req rotateCredentialRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		niahttp.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	ctx := r.Context()
	operator := resolveOperator(ctx, req.RotatedBy)
	old, err := s.creds.Get(ctx, id)
	if err != nil {
		if errors.Is(err, credentials.ErrNotFound) {
			niahttp.WriteError(w, http.StatusNotFound, "credential not found")
			return
		}
		niahttp.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	var ttl time.Duration
	if req.TTLSeconds > 0 {
		ttl = time.Duration(req.TTLSeconds) * time.Second
	}
	next, secret, err := s.creds.Rotate(ctx, id, operator, ttl)
	if err != nil {
		niahttp.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.graphAddNode(ctx, next.ID, graph.NodeCredential)
	s.graphAddEdge(ctx, next.ID, next.AgentRef, graph.EdgeBoundTo)
	s.audit(ctx, audit.Event{
		Action:   "credential.rotated",
		AgentRef: old.AgentRef,
		Operator: operator,
		Detail:   fmt.Sprintf("%s superseded by %s", id, next.ID),
		At:       time.Now(),
	})
	niahttp.WriteJSON(w, http.StatusCreated, issuedCredential{Credential: next, Secret: secret})
}

type registerToolRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Transport   string `json:"transport"`
	RiskClass   string `json:"risk_class"`
	Owner       string `json:"owner"`
}

// handleRegisterTool onboards a callable tool into the catalog the
// gateway will eventually consult before forwarding a call. Not audited:
// audit.Event's AgentRef is documented as "the subject the event is
// about", an agent identity, and a tool has no agent to attach an event
// to, the same reasoning the gateway already applies to an unresolved
// caller. A tool-centric trail is a real gap, not an oversight, see
// docs/ARCHITECTURE.md's audit trail row.
func (s *server) handleRegisterTool(w http.ResponseWriter, r *http.Request) {
	var req registerToolRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		niahttp.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Name == "" {
		niahttp.WriteError(w, http.StatusBadRequest, "name is required")
		return
	}
	risk := tools.RiskClass(req.RiskClass)
	switch risk {
	case tools.RiskReadOnly, tools.RiskWrite, tools.RiskDestructive:
	case "":
		risk = tools.RiskReadOnly
	default:
		niahttp.WriteError(w, http.StatusBadRequest, "risk_class must be one of read_only, write, destructive")
		return
	}

	tool := tools.Tool{
		Name:        req.Name,
		Description: req.Description,
		Transport:   req.Transport,
		RiskClass:   risk,
		Owner:       req.Owner,
	}
	ctx := r.Context()
	if err := s.toolCat.Register(ctx, tool); err != nil {
		// Same fix as handleRegisterAgent above and for the same reason,
		// see docs/SECURITY_INVARIANTS.md: only an actual duplicate is a
		// 409, anything else is a 500.
		if errors.Is(err, tools.ErrAlreadyRegistered) {
			s.metrics.toolRegistrations.Inc("duplicate")
			niahttp.WriteError(w, http.StatusConflict, err.Error())
			return
		}
		s.metrics.toolRegistrations.Inc("error")
		niahttp.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.metrics.toolRegistrations.Inc("created")
	s.graphAddNode(ctx, tool.Name, graph.NodeTool)
	niahttp.WriteJSON(w, http.StatusCreated, tool)
}

func (s *server) handleListTools(w http.ResponseWriter, r *http.Request) {
	list, err := s.toolCat.List(r.Context())
	if err != nil {
		niahttp.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	niahttp.WriteJSON(w, http.StatusOK, list)
}

func (s *server) handleGetTool(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "" {
		niahttp.WriteError(w, http.StatusBadRequest, "tool name is required")
		return
	}
	tool, err := s.toolCat.Get(r.Context(), name)
	if err != nil {
		if errors.Is(err, tools.ErrNotFound) {
			niahttp.WriteError(w, http.StatusNotFound, "tool not found")
			return
		}
		niahttp.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	niahttp.WriteJSON(w, http.StatusOK, tool)
}

// grantWire is a policy.Grant on the wire: only the fields relevant to
// Kind are meaningful, the rest are left at their zero value, same
// shape policy.Grant itself uses.
type grantWire struct {
	Kind   string `json:"kind"`
	Group  string `json:"group,omitempty"`
	Method string `json:"method,omitempty"`
	Path   string `json:"path,omitempty"`
	Object string `json:"object,omitempty"`
}

func grantFromWire(w grantWire) (policy.Grant, error) {
	switch w.Kind {
	case "api_group":
		if w.Group == "" {
			return policy.Grant{}, errors.New("api_group grant requires group")
		}
		return policy.GrantForAPIGroup(w.Group), nil
	case "endpoint":
		if w.Method == "" || w.Path == "" {
			return policy.Grant{}, errors.New("endpoint grant requires method and path")
		}
		return policy.GrantForEndpoint(w.Method, w.Path), nil
	case "tool":
		if w.Object == "" {
			return policy.Grant{}, errors.New("tool grant requires object")
		}
		return policy.GrantForTool(w.Object), nil
	case "data":
		if w.Object == "" {
			return policy.Grant{}, errors.New("data grant requires object")
		}
		return policy.GrantForData(w.Object), nil
	default:
		return policy.Grant{}, fmt.Errorf("unknown grant kind %q, want one of api_group, endpoint, tool, data", w.Kind)
	}
}

func grantsFromWire(in []grantWire) ([]policy.Grant, error) {
	out := make([]policy.Grant, 0, len(in))
	for _, w := range in {
		g, err := grantFromWire(w)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, nil
}

type writeGrantsRequest struct {
	Grants   []grantWire `json:"grants"`
	Operator string      `json:"operator"`
}

// handleWriteGrants is Permissions' missing HTTP surface: internal/policy
// has had WriteGrants on the Client interface since the beginning, and
// TesseraHTTPClient/InMemoryClient both implement it, but until now
// nothing outside a test ever called it over HTTP, an operator had no
// way to actually grant an agent anything through cmd/api or niactl.
// Requires the agent to already be registered, same reasoning as
// handleIssueCredential: granting isn't a backdoor way to create an
// identity record.
func (s *server) handleWriteGrants(w http.ResponseWriter, r *http.Request) {
	ref := r.PathValue("ref")
	if ref == "" {
		niahttp.WriteError(w, http.StatusBadRequest, "agent ref is required")
		return
	}
	ctx := r.Context()
	if _, err := s.agents.Get(ctx, ref); err != nil {
		niahttp.WriteError(w, http.StatusNotFound, "agent not registered")
		return
	}

	var req writeGrantsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		niahttp.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.Grants) == 0 {
		niahttp.WriteError(w, http.StatusBadRequest, "grants is required and must be non-empty")
		return
	}
	grants, err := grantsFromWire(req.Grants)
	if err != nil {
		niahttp.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := s.pol.WriteGrants(ctx, ref, grants); err != nil {
		if errors.Is(err, policy.ErrKilled) {
			s.metrics.grantsWritten.Inc("killed")
			niahttp.WriteError(w, http.StatusConflict, "agent is killed, restore before writing grants")
			return
		}
		s.metrics.grantsWritten.Inc("error")
		niahttp.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.metrics.grantsWritten.Inc("success")
	s.graphAddGrantEdges(ctx, ref, grants)
	s.audit(ctx, audit.Event{
		Action:   "grant.written",
		AgentRef: ref,
		Operator: resolveOperator(ctx, req.Operator),
		Detail:   grantSummary(grants),
		At:       time.Now(),
	})

	updated, err := s.pol.ListGrants(ctx, ref)
	if err != nil {
		niahttp.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	niahttp.WriteJSON(w, http.StatusOK, updated)
}

// handleDeleteGrants removes specific grants without touching the rest
// of the agent's declared state, the same "smaller than a kill" posture
// handleRevokeCredential takes relative to handleKill.
func (s *server) handleDeleteGrants(w http.ResponseWriter, r *http.Request) {
	ref := r.PathValue("ref")
	if ref == "" {
		niahttp.WriteError(w, http.StatusBadRequest, "agent ref is required")
		return
	}
	ctx := r.Context()
	if _, err := s.agents.Get(ctx, ref); err != nil {
		niahttp.WriteError(w, http.StatusNotFound, "agent not registered")
		return
	}

	var req writeGrantsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		niahttp.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.Grants) == 0 {
		niahttp.WriteError(w, http.StatusBadRequest, "grants is required and must be non-empty")
		return
	}
	grants, err := grantsFromWire(req.Grants)
	if err != nil {
		niahttp.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := s.pol.DeleteGrants(ctx, ref, grants); err != nil {
		s.metrics.grantsDeleted.Inc("error")
		niahttp.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.metrics.grantsDeleted.Inc("success")
	s.audit(ctx, audit.Event{
		Action:   "grant.deleted",
		AgentRef: ref,
		Operator: resolveOperator(ctx, req.Operator),
		Detail:   grantSummary(grants),
		At:       time.Now(),
	})

	updated, err := s.pol.ListGrants(ctx, ref)
	if err != nil {
		niahttp.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	niahttp.WriteJSON(w, http.StatusOK, updated)
}

func (s *server) handleListGrants(w http.ResponseWriter, r *http.Request) {
	ref := r.PathValue("ref")
	if ref == "" {
		niahttp.WriteError(w, http.StatusBadRequest, "agent ref is required")
		return
	}
	grants, err := s.pol.ListGrants(r.Context(), ref)
	if err != nil {
		niahttp.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	niahttp.WriteJSON(w, http.StatusOK, grants)
}

func grantSummary(grants []policy.Grant) string {
	parts := make([]string, 0, len(grants))
	for _, g := range grants {
		switch g.Kind {
		case "api_group":
			parts = append(parts, "api_group:"+g.Group)
		case "endpoint":
			parts = append(parts, "endpoint:"+g.Method+" "+g.Path)
		default:
			parts = append(parts, g.Kind+":"+g.Object)
		}
	}
	return strings.Join(parts, ", ")
}

type addGraphNodeRequest struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
}

// handleAddGraphNode adds one node to the identity graph by hand. Agent
// registration, tool registration, credential issuance, and grant
// writes all add their own nodes automatically now (see
// graphAddNode/graphAddEdge and their call sites above), so this
// endpoint's real remaining job is the node kind nothing else creates
// on its own, Human, an operator or team accountable for an agent,
// internal/registry has no concept of a human at all. It's also still
// how an operator adds a node for something NIA doesn't otherwise track
// (a data resource nobody has granted yet but wants represented in the
// graph ahead of time), or repairs the graph by hand if something ever
// gets out of sync with it.
func (s *server) handleAddGraphNode(w http.ResponseWriter, r *http.Request) {
	var req addGraphNodeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		niahttp.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.ID == "" {
		niahttp.WriteError(w, http.StatusBadRequest, "id is required")
		return
	}
	kind := graph.NodeKind(req.Kind)
	switch kind {
	case graph.NodeHuman, graph.NodeAgent, graph.NodeTool, graph.NodeData, graph.NodeCredential:
	default:
		niahttp.WriteError(w, http.StatusBadRequest, "kind must be one of human, agent, tool, data, credential")
		return
	}

	node := graph.Node{ID: req.ID, Kind: kind}
	if err := s.graph.AddNode(r.Context(), node); err != nil {
		niahttp.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	niahttp.WriteJSON(w, http.StatusCreated, node)
}

type addGraphEdgeRequest struct {
	From string `json:"from"`
	To   string `json:"to"`
	Kind string `json:"kind"`
}

// validGraphEdgeKind is shared by the add-edge, neighbors, and reachable
// handlers, all three take an EdgeKind off the wire and need the same
// check against the six kinds internal/graph actually defines.
func validGraphEdgeKind(k graph.EdgeKind) bool {
	switch k {
	case graph.EdgeOwns, graph.EdgeDelegatesTo, graph.EdgeTrusts, graph.EdgeMemberOf, graph.EdgeGrants, graph.EdgeBoundTo:
		return true
	default:
		return false
	}
}

const graphEdgeKindHelp = "kind must be one of owns, delegates_to, trusts, member_of, grants, bound_to"

// handleAddGraphEdge adds one edge. It does not require either endpoint
// to already exist as a node, InMemoryGraph.AddEdge itself has no such
// constraint (see internal/graph/graph.go), Neighbors and Reachable
// simply won't resolve an edge whose target was never added as a node.
// Enforcing referential integrity here would be a real feature, not
// free, and nothing has needed it yet.
func (s *server) handleAddGraphEdge(w http.ResponseWriter, r *http.Request) {
	var req addGraphEdgeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		niahttp.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.From == "" || req.To == "" {
		niahttp.WriteError(w, http.StatusBadRequest, "from and to are required")
		return
	}
	kind := graph.EdgeKind(req.Kind)
	if !validGraphEdgeKind(kind) {
		niahttp.WriteError(w, http.StatusBadRequest, graphEdgeKindHelp)
		return
	}

	edge := graph.Edge{From: req.From, To: req.To, Kind: kind}
	if err := s.graph.AddEdge(r.Context(), edge); err != nil {
		niahttp.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	niahttp.WriteJSON(w, http.StatusCreated, edge)
}

// handleGraphNeighbors answers "what does this node point at directly
// through one specific edge kind," the one-hop version of the
// blast-radius question handleGraphReachable answers transitively.
func (s *server) handleGraphNeighbors(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		niahttp.WriteError(w, http.StatusBadRequest, "node id is required")
		return
	}
	raw := r.URL.Query().Get("kind")
	if raw == "" {
		niahttp.WriteError(w, http.StatusBadRequest, "kind query parameter is required")
		return
	}
	kind := graph.EdgeKind(raw)
	if !validGraphEdgeKind(kind) {
		niahttp.WriteError(w, http.StatusBadRequest, graphEdgeKindHelp)
		return
	}

	nodes, err := s.graph.Neighbors(r.Context(), id, kind)
	if err != nil {
		niahttp.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	niahttp.WriteJSON(w, http.StatusOK, nodes)
}

// allGraphEdgeKinds is handleGraphReachable's default when the caller
// doesn't narrow the query with ?kinds=, the blast-radius question
// usually wants "everything reachable, however it's reachable," not one
// relation type at a time.
var allGraphEdgeKinds = []graph.EdgeKind{
	graph.EdgeOwns, graph.EdgeDelegatesTo, graph.EdgeTrusts, graph.EdgeMemberOf, graph.EdgeGrants, graph.EdgeBoundTo,
}

// handleGraphReachable is the blast-radius query from
// docs/DATA_MODEL.md and internal/graph/graph_test.go: given a node,
// what else can it reach, directly or transitively, through the given
// edge kinds. This is the question a live OpenFGA check can't answer on
// its own, see internal/graph's package doc comment for why the two are
// kept separate. The result is discovered/historical reachability, not
// a live authorization list, deleting a grant does not remove the edge
// it added (see graphAddGrantEdges below), a node appearing here is not
// proof it's still authorized today, internal/policy (GET
// /agents/{ref}/grants, or a direct Check) is the only current-truth
// answer to that question.
func (s *server) handleGraphReachable(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		niahttp.WriteError(w, http.StatusBadRequest, "node id is required")
		return
	}

	kinds, ok := parseGraphEdgeKinds(r)
	if !ok {
		niahttp.WriteError(w, http.StatusBadRequest, graphEdgeKindHelp)
		return
	}

	nodes, err := s.graph.Reachable(r.Context(), id, kinds)
	if err != nil {
		niahttp.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	niahttp.WriteJSON(w, http.StatusOK, nodes)
}

// parseGraphEdgeKinds is handleGraphReachable and handleBlastRadius's
// shared ?kinds= parsing: a comma-separated list of edge kinds, or
// every edge kind when the query param is omitted, same "everything
// reachable, however" default both endpoints want. The bool return is
// false on an unknown kind, the caller decides how to report that.
func parseGraphEdgeKinds(r *http.Request) ([]graph.EdgeKind, bool) {
	raw := r.URL.Query().Get("kinds")
	if raw == "" {
		return allGraphEdgeKinds, true
	}
	parts := strings.Split(raw, ",")
	kinds := make([]graph.EdgeKind, 0, len(parts))
	for _, p := range parts {
		kind := graph.EdgeKind(strings.TrimSpace(p))
		if !validGraphEdgeKind(kind) {
			return nil, false
		}
		kinds = append(kinds, kind)
	}
	return kinds, true
}

// blastRadius is handleBlastRadius's response shape: Summary's counts
// plus what the graph alone can't say, which of the reachable data
// resources are actually sensitive, and a severity call an incident
// review can read in one glance rather than adding up ByKind itself.
// See handleBlastRadius's own doc comment for exactly how Severity is
// decided, a fixed, explainable rule, not a score nobody can reproduce.
type blastRadius struct {
	ID                 string                 `json:"id"`
	Total              int                    `json:"total"`
	ByKind             map[graph.NodeKind]int `json:"by_kind"`
	CriticalResources  []string               `json:"critical_resources"`
	SensitiveResources []string               `json:"sensitive_resources"`
	Severity           string                 `json:"severity"`
}

// handleBlastRadius answers the question docs/ARCHITECTURE.md's
// identity graph section poses but handleGraphReachable alone doesn't:
// not just what's reachable, but how much, and how bad. Severity is a
// fixed, explainable rule over what Reachable and internal/sensitivity
// already know, not a tuned score: HIGH if anything reachable
// classifies sensitivity.Critical, or five or more reachable nodes are
// themselves agents or tools (a wide blast radius of controllable
// things, even without touching data an operator flagged as critical);
// MEDIUM if anything reachable classifies sensitivity.Sensitive, or at
// least one reachable node is an agent or tool; LOW otherwise. This is
// deliberately simple and stated plainly here so it's easy to argue
// with and cheap to change, the same posture internal/sensitivity's own
// rule-based classification takes, explainable over sophisticated.
// s.sensitive nil (no NIA_SENSITIVITY_RULES_PATH configured) means
// every data resource classifies Public, so CriticalResources and
// SensitiveResources both always come back empty in that case, not an
// error, just nothing declared sensitive yet.
//
// Same caveat as handleGraphReachable above, worth repeating here since
// this is the endpoint most likely to get read as "here's what this
// agent can currently do": the reachable set, and therefore this
// severity call, can include resources the agent was granted at some
// point and had that grant later revoked, the graph does not drop the
// edge. Treat a HIGH here as "here's what this agent's history in the
// graph could reach," corroborate against internal/policy's live grants
// before treating it as a statement about current exposure.
func (s *server) handleBlastRadius(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		niahttp.WriteError(w, http.StatusBadRequest, "node id is required")
		return
	}

	kinds, ok := parseGraphEdgeKinds(r)
	if !ok {
		niahttp.WriteError(w, http.StatusBadRequest, graphEdgeKindHelp)
		return
	}

	nodes, err := s.graph.Reachable(r.Context(), id, kinds)
	if err != nil {
		niahttp.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}

	summary := graph.Summarize(nodes)
	critical := []string{}
	sensitiveResources := []string{}
	if s.sensitive != nil {
		for _, n := range nodes {
			if n.Kind != graph.NodeData {
				continue
			}
			switch s.sensitive.Classify(n.ID) {
			case sensitivity.Critical:
				critical = append(critical, n.ID)
			case sensitivity.Sensitive:
				sensitiveResources = append(sensitiveResources, n.ID)
			}
		}
	}

	controllable := summary.ByKind[graph.NodeAgent] + summary.ByKind[graph.NodeTool]
	severity := "LOW"
	switch {
	case len(critical) > 0 || controllable >= 5:
		severity = "HIGH"
	case len(sensitiveResources) > 0 || controllable >= 1:
		severity = "MEDIUM"
	}

	niahttp.WriteJSON(w, http.StatusOK, blastRadius{
		ID:                 id,
		Total:              summary.Total,
		ByKind:             summary.ByKind,
		CriticalResources:  critical,
		SensitiveResources: sensitiveResources,
		Severity:           severity,
	})
}

// audit appends one event, logging rather than silently dropping a
// failure: on a security control plane, an action that didn't make it
// into the trail is worth knowing about even when there's nothing this
// handler can do about it mid-request.
func (s *server) audit(ctx context.Context, evt audit.Event) {
	if err := s.auditLog.Append(ctx, evt); err != nil {
		s.metrics.auditWriteFailures.Inc()
		log.Printf("nia-api: audit append failed: %v", err)
	}
}

// graphAddNode and graphAddEdge are what auto-populates the identity
// graph from what's already known elsewhere: an agent registering, a
// tool registering, a grant being written. Before this, an operator had
// to add every node and edge by hand through niactl graph add-node/
// add-edge for the graph to know anything at all, which meant a
// blast-radius query on a freshly registered agent came back empty even
// though the control plane already knew that agent existed. Both are
// fail-open the same way s.audit is: the thing that actually mattered
// (the registration, the grant) already succeeded, a graph write
// failing alongside it is logged, not turned into a failed response,
// AddNode and AddEdge on the in-memory implementation never actually
// fail today, this exists for whatever backs Graph next.
func (s *server) graphAddNode(ctx context.Context, id string, kind graph.NodeKind) {
	if err := s.graph.AddNode(ctx, graph.Node{ID: id, Kind: kind}); err != nil {
		s.metrics.graphWriteFailures.Inc("add_node")
		log.Printf("nia-api: graph add node failed: %v", err)
	}
}

func (s *server) graphAddEdge(ctx context.Context, from, to string, kind graph.EdgeKind) {
	if err := s.graph.AddEdge(ctx, graph.Edge{From: from, To: to, Kind: kind}); err != nil {
		s.metrics.graphWriteFailures.Inc("add_edge")
		log.Printf("nia-api: graph add edge failed: %v", err)
	}
}

// graphAddGrantEdges is handleWriteGrants' hook into the graph: a tool
// or data grant is also a grants edge, agent -> object, the same fact
// internal/policy just recorded for live authorization, recorded a
// second way for traversal. api_group and endpoint grants have no
// natural node on either side of them, nothing here represents an API
// group or a URL path, so those two kinds are skipped, not an
// oversight. The object node (a tool or a data resource) is added if it
// doesn't already exist, AddNode is idempotent, a grant naming a tool
// or resource nobody separately registered still gets a node so the
// edge has somewhere to point.
//
// handleDeleteGrants deliberately does not call a mirror of this.
// internal/graph.Graph has no edge removal primitive, and isn't
// getting one, see that package's doc comment: the graph is
// historical and append-only by design, a revoked grant still shows
// up as a reachable edge in a blast-radius query, and that's the
// intended behavior, not a bug waiting on a fix. internal/policy's
// ListGrants (or a direct Check) is the only place to ask "what's
// granted right now," an operator or an automated consumer reading
// graph reachability as current authorization is misusing this
// endpoint, not hitting a known limitation of it. See
// TestGraphEdgeSurvivesGrantDeletion_ButPolicyCheckReflectsCurrentTruth
// in cmd/api/graph_test.go for the concrete proof of both halves of
// that statement together, and docs/SECURITY_INVARIANTS.md for this
// stated as an invariant.
func (s *server) graphAddGrantEdges(ctx context.Context, ref string, grants []policy.Grant) {
	for _, g := range grants {
		switch g.Kind {
		case "tool":
			s.graphAddNode(ctx, g.Object, graph.NodeTool)
			s.graphAddEdge(ctx, ref, g.Object, graph.EdgeGrants)
		case "data":
			s.graphAddNode(ctx, g.Object, graph.NodeData)
			s.graphAddEdge(ctx, ref, g.Object, graph.EdgeGrants)
		}
	}
}

// auditLimitDefault and auditLimitMax bound the recent-events query.
// Unbounded would let one request pull the entire in-memory sink (or,
// once there's a real backend, scan a very large table) into a single
// JSON response.
const (
	auditLimitDefault = 100
	auditLimitMax     = 1000
)

func (s *server) handleRecentAudit(w http.ResponseWriter, r *http.Request) {
	limit := auditLimitDefault
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 {
			niahttp.WriteError(w, http.StatusBadRequest, "limit must be a positive integer")
			return
		}
		limit = n
	}
	if limit > auditLimitMax {
		limit = auditLimitMax
	}
	events, err := s.auditLog.Recent(r.Context(), limit)
	if err != nil {
		niahttp.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	niahttp.WriteJSON(w, http.StatusOK, events)
}

func (s *server) handleAgentAudit(w http.ResponseWriter, r *http.Request) {
	ref := r.PathValue("ref")
	if ref == "" {
		niahttp.WriteError(w, http.StatusBadRequest, "agent ref is required")
		return
	}
	events, err := s.auditLog.ForAgent(r.Context(), ref)
	if err != nil {
		niahttp.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	niahttp.WriteJSON(w, http.StatusOK, events)
}

// handleVerifyAudit is the verification operation the hardening
// directive asked for as its own thing, not folded into a general
// health check: it walks the entire stored audit chain and reports,
// in full, whether it's intact, not just yes or no, see
// internal/audit/chain.go's Verify and VerifyResult. s.auditLog is
// typed as audit.Store, the narrower read/write interface every other
// audit handler in this file uses, so this handler type-asserts to
// audit.Chained rather than widening that field's declared type for
// one endpoint; both concrete Stores this codebase ships
// (InMemorySink, PostgresSink) implement Chained, a Store that
// doesn't (a future SIEM-forwarding Sink, say) reports 501 here
// rather than panicking or silently claiming a clean chain it never
// actually checked.
func (s *server) handleVerifyAudit(w http.ResponseWriter, r *http.Request) {
	chained, ok := s.auditLog.(audit.Chained)
	if !ok {
		niahttp.WriteError(w, http.StatusNotImplemented, "this audit backend does not support chain verification")
		return
	}
	ctx := r.Context()

	// When checkpointing is configured and something has been anchored,
	// verify against it too. That is the only check that can catch a
	// consistent rewrite: the chain walk below would report clean either
	// way, because a rewritten chain is a valid chain over the wrong
	// events.
	if s.checkpointer.Configured() {
		cp, err := s.checkpointStore.Latest(ctx)
		switch {
		case err == nil:
			out, err := s.checkpointer.VerifyAgainst(ctx, chained, cp)
			if err != nil {
				niahttp.WriteError(w, http.StatusInternalServerError, err.Error())
				return
			}
			niahttp.WriteJSON(w, http.StatusOK, out)
			return
		case errors.Is(err, audit.ErrNoCheckpoints):
			// Configured but nothing anchored yet. Fall through to the
			// plain chain check: a deployment that has never taken a
			// checkpoint is not broken.
		default:
			niahttp.WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}

	result, err := audit.Verify(ctx, chained)
	if err != nil {
		niahttp.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	niahttp.WriteJSON(w, http.StatusOK, result)
}

// handleCreateCheckpoint signs the audit chain's current tip and stores
// the result. A write rather than a read: it changes what the deployment
// can later prove, and an operator with only read access should not be
// able to plant anchors.
func (s *server) handleCreateCheckpoint(w http.ResponseWriter, r *http.Request) {
	chained, ok := s.auditLog.(audit.Chained)
	if !ok {
		niahttp.WriteError(w, http.StatusNotImplemented, "this audit backend does not support chain verification")
		return
	}
	if !s.checkpointer.Configured() {
		niahttp.WriteError(w, http.StatusNotImplemented, "no audit checkpoint signing key is configured, set NIA_AUDIT_CHECKPOINT_KEY")
		return
	}

	ctx := r.Context()
	cp, result, err := s.checkpointer.Create(ctx, chained)
	if err != nil {
		// A chain that does not verify is a 409 rather than a 500: the
		// request was well formed and the refusal is a finding about the
		// data, not a failure of this process. Signing a broken chain
		// would later read as proof the damage was legitimate history.
		if !result.OK {
			niahttp.WriteJSON(w, http.StatusConflict, map[string]any{"error": err.Error(), "verify": result})
			return
		}
		niahttp.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.checkpointStore.Save(ctx, cp); err != nil {
		niahttp.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(ctx, audit.Event{
		Action:   "audit.checkpoint_created",
		Operator: resolveOperator(ctx, ""),
		Detail:   fmt.Sprintf("seq=%d hash=%s", cp.Seq, cp.Hash),
		At:       time.Now(),
	})
	niahttp.WriteJSON(w, http.StatusCreated, cp)
}

// handleListCheckpoints returns recent checkpoints so an operator can
// archive them somewhere the audit database cannot reach, which is the
// only way the anchor survives an attacker who owns that database.
func (s *server) handleListCheckpoints(w http.ResponseWriter, r *http.Request) {
	list, err := s.checkpointStore.List(r.Context(), 50)
	if err != nil {
		niahttp.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	niahttp.WriteJSON(w, http.StatusOK, list)
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()

	// Every route below declares the permission it needs, next to the
	// route rather than in a table somewhere else, so the answer to
	// "who can do this" is visible at the point the route is defined.
	// read is anything that only looks, write changes what exists, and
	// kill is the switch plus its restore, separated because its
	// consequence is immediate and total: it deletes an agent's tuples
	// and cascades into revoking every credential it holds. See
	// internal/opauth/roles.go.
	//
	// GET /healthz and GET /metrics take no permission for the same
	// reason opauth.Middleware exempts them from authentication.
	read := func(h http.HandlerFunc) http.Handler { return opauth.Require(opauth.PermRead, h) }
	write := func(h http.HandlerFunc) http.Handler { return opauth.Require(opauth.PermWrite, h) }
	kill := func(h http.HandlerFunc) http.Handler { return opauth.Require(opauth.PermKill, h) }

	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.Handle("POST /agents", write(s.handleRegisterAgent))
	mux.Handle("GET /agents", read(s.handleListAgents))
	mux.Handle("GET /agents/{ref}", read(s.handleGetAgent))
	mux.Handle("POST /policy/kill", kill(s.handleKill))
	mux.Handle("POST /policy/restore", kill(s.handleRestore))
	mux.Handle("POST /agents/{ref}/grants", write(s.handleWriteGrants))
	mux.Handle("DELETE /agents/{ref}/grants", write(s.handleDeleteGrants))
	mux.Handle("GET /agents/{ref}/grants", read(s.handleListGrants))
	mux.Handle("POST /agents/{ref}/credentials", write(s.handleIssueCredential))
	mux.Handle("GET /agents/{ref}/credentials", read(s.handleListCredentials))
	mux.Handle("POST /credentials/{id}/revoke", write(s.handleRevokeCredential))
	mux.Handle("POST /credentials/{id}/disable", write(s.handleDisableCredential))
	mux.Handle("POST /credentials/{id}/enable", write(s.handleEnableCredential))
	mux.Handle("POST /credentials/{id}/rotate", write(s.handleRotateCredential))
	mux.Handle("POST /tools", write(s.handleRegisterTool))
	mux.Handle("GET /tools", read(s.handleListTools))
	mux.Handle("GET /tools/{name}", read(s.handleGetTool))
	mux.Handle("GET /audit", read(s.handleRecentAudit))
	mux.Handle("GET /agents/{ref}/audit", read(s.handleAgentAudit))
	mux.Handle("GET /audit/verify", read(s.handleVerifyAudit))
	mux.Handle("POST /audit/checkpoint", write(s.handleCreateCheckpoint))
	mux.Handle("GET /audit/checkpoint", read(s.handleListCheckpoints))
	mux.Handle("POST /graph/nodes", write(s.handleAddGraphNode))
	mux.Handle("POST /graph/edges", write(s.handleAddGraphEdge))
	mux.Handle("GET /graph/{id}/neighbors", read(s.handleGraphNeighbors))
	mux.Handle("GET /graph/{id}/reachable", read(s.handleGraphReachable))
	mux.Handle("GET /graph/{id}/blast-radius", read(s.handleBlastRadius))
	mux.Handle("GET /metrics", s.metricsReg)
	// routes() returns http.Handler rather than *http.ServeMux
	// specifically so this wrap is possible: when operator auth is
	// configured, every request goes through operatorAuthMiddleware
	// before it ever reaches a handler; when it isn't, this returns
	// the bare mux, identical to before opauth existed. Every caller
	// (main, and every test in this package) only ever calls
	// ServeHTTP on the result, which http.Handler still provides.
	var h http.Handler = mux
	if s.opStore != nil {
		h = operatorAuthMiddleware(s.opStore, h)
	}
	// Order matters, outermost first: rate limit, then body cap, then
	// authentication, then the handler. Limiting in front of
	// authentication is the point, an attacker who never presents a
	// valid token still costs this process work. Capping the body in
	// front of it too means an oversized request is refused before any
	// handler reads a byte of it.
	h = niahttp.MaxBytes(h, niahttp.DefaultMaxRequestBytes)
	h = ratelimit.Middleware(s.limiter, s.trustForwarded, func(string) {
		s.metrics.rateLimited.Inc()
	}, h, "/healthz")
	return h
}

func main() {
	addr := os.Getenv("NIA_API_ADDR")
	if addr == "" {
		addr = ":8080"
	}

	s, err := newServer(context.Background())
	if err != nil {
		log.Fatalf("nia-api: %v", err)
	}
	if s.opStore != nil {
		log.Printf("nia-api: operator authentication is on, every request except GET /healthz and GET /metrics requires Authorization: Bearer <operator token>")
	}
	srv := &http.Server{
		Addr:    addr,
		Handler: s.routes(),
		// Only ReadHeaderTimeout was set before, which bounds the
		// headers and nothing else: a client could open a connection,
		// send valid headers, and then trickle a body or simply hold
		// the connection open indefinitely, and enough of those exhaust
		// the process without sending a single complete request.
		// ReadTimeout bounds the whole request, WriteTimeout the whole
		// response, IdleTimeout an otherwise-silent keep-alive
		// connection, and MaxHeaderBytes the headers themselves, which
		// are read before any of this code runs and so are not covered
		// by the body cap in routes().
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}

	log.Printf("nia-api listening on %s", addr)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("nia-api: %v", err)
	}
}
