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
	"time"

	"github.com/bogdanticu88/nia/internal/audit"
	"github.com/bogdanticu88/nia/internal/credentials"
	"github.com/bogdanticu88/nia/internal/identity"
	"github.com/bogdanticu88/nia/internal/policy"
	"github.com/bogdanticu88/nia/internal/registry"
	"github.com/bogdanticu88/nia/internal/registry/tools"
	niahttp "github.com/bogdanticu88/nia/internal/transport/http"
)

// server wires every control-plane dependency together. Every field is
// an interface; main() below is the only place that decides which
// implementation (in-memory reference vs. a real Postgres/Tessera-backed
// one) satisfies it. Swapping the policy client for a real Tessera HTTP
// adapter, once it exists, touches only this constructor.
type server struct {
	agents   registry.AgentRegistry
	toolCat  tools.Catalog
	creds    credentials.Store
	pol      policy.Client
	auditLog audit.Store
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
	pol, err := policy.FromEnv()
	if err != nil {
		return nil, fmt.Errorf("nia-api: %w", err)
	}
	auditLog, err := audit.FromEnv(ctx)
	if err != nil {
		return nil, fmt.Errorf("nia-api: %w", err)
	}
	return &server{
		agents:   registry.NewInMemoryAgentRegistry(),
		toolCat:  tools.NewInMemoryCatalog(),
		creds:    credentials.NewInMemoryStore(),
		pol:      pol,
		auditLog: auditLog,
	}, nil
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
		niahttp.WriteError(w, http.StatusConflict, err.Error())
		return
	}
	s.audit(ctx, audit.Event{
		Action:   "agent.registered",
		AgentRef: agent.Ref,
		Operator: req.Owner,
		At:       time.Now(),
	})
	niahttp.WriteJSON(w, http.StatusCreated, agent)
}

func (s *server) handleListAgents(w http.ResponseWriter, r *http.Request) {
	agents, err := s.agents.List(r.Context())
	if err != nil {
		niahttp.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	niahttp.WriteJSON(w, http.StatusOK, agents)
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
	result, err := s.pol.Kill(ctx, req.AgentRef, req.Incident, req.Operator)
	if err != nil {
		niahttp.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.agents.SetState(ctx, req.AgentRef, identity.StateKilled)
	s.audit(ctx, audit.Event{
		Action:   "agent.killed",
		AgentRef: req.AgentRef,
		Operator: req.Operator,
		Incident: req.Incident,
		At:       time.Now(),
	})
	niahttp.WriteJSON(w, http.StatusOK, result)
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

	cred, err := s.creds.Issue(ctx, ref, kind, ttl)
	if err != nil {
		niahttp.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(ctx, audit.Event{
		Action:   "credential.issued",
		AgentRef: ref,
		Operator: req.Operator,
		Detail:   string(kind) + " " + cred.ID,
		At:       time.Now(),
	})
	niahttp.WriteJSON(w, http.StatusCreated, cred)
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
	cred, err := s.creds.Get(ctx, id)
	if err != nil {
		if errors.Is(err, credentials.ErrNotFound) {
			niahttp.WriteError(w, http.StatusNotFound, "credential not found")
			return
		}
		niahttp.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.creds.Revoke(ctx, id, req.RevokedBy, req.Reason); err != nil {
		niahttp.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(ctx, audit.Event{
		Action:   "credential.revoked",
		AgentRef: cred.AgentRef,
		Operator: req.RevokedBy,
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

// audit appends one event, logging rather than silently dropping a
// failure: on a security control plane, an action that didn't make it
// into the trail is worth knowing about even when there's nothing this
// handler can do about it mid-request.
func (s *server) audit(ctx context.Context, evt audit.Event) {
	if err := s.auditLog.Append(ctx, evt); err != nil {
		log.Printf("nia-api: audit append failed: %v", err)
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

func (s *server) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("POST /agents", s.handleRegisterAgent)
	mux.HandleFunc("GET /agents", s.handleListAgents)
	mux.HandleFunc("POST /policy/kill", s.handleKill)
	mux.HandleFunc("POST /agents/{ref}/credentials", s.handleIssueCredential)
	mux.HandleFunc("GET /agents/{ref}/credentials", s.handleListCredentials)
	mux.HandleFunc("POST /credentials/{id}/revoke", s.handleRevokeCredential)
	mux.HandleFunc("GET /audit", s.handleRecentAudit)
	mux.HandleFunc("GET /agents/{ref}/audit", s.handleAgentAudit)
	return mux
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
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("nia-api listening on %s", addr)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("nia-api: %v", err)
	}
}
