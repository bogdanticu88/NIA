// cmd/api is the NIA control-plane API: agent registration, NHI
// inventory, credential issuance, tool registration, permission
// grants (proxied to the policy client), audit query, and kill/restore.
// This is not the hot path; the gateway (cmd/gateway) is. This service
// manages the state the gateway's live checks read.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
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
	auditLog audit.Sink
}

// newServer wires every control-plane dependency. The policy client comes
// from policy.FromEnv: NIA_TESSERA_BASE_URL unset means the in-memory
// reference client, no Tessera required to run this locally, set it and
// the required signing key alongside it and this talks to a real Tessera
// instance instead. See internal/policy/from_env.go for the full env var
// list and internal/policy/tessera_client.go's doc comment for what
// TesseraHTTPClient does and doesn't guarantee relative to the in-memory
// one.
func newServer() (*server, error) {
	pol, err := policy.FromEnv()
	if err != nil {
		return nil, fmt.Errorf("nia-api: %w", err)
	}
	return &server{
		agents:   registry.NewInMemoryAgentRegistry(),
		toolCat:  tools.NewInMemoryCatalog(),
		creds:    credentials.NewInMemoryStore(),
		pol:      pol,
		auditLog: audit.NewInMemorySink(10_000),
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
	_ = s.auditLog.Append(ctx, audit.Event{
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
	_ = s.auditLog.Append(ctx, audit.Event{
		Action:   "agent.killed",
		AgentRef: req.AgentRef,
		Operator: req.Operator,
		Incident: req.Incident,
		At:       time.Now(),
	})
	niahttp.WriteJSON(w, http.StatusOK, result)
}

func (s *server) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("POST /agents", s.handleRegisterAgent)
	mux.HandleFunc("GET /agents", s.handleListAgents)
	mux.HandleFunc("POST /policy/kill", s.handleKill)
	return mux
}

func main() {
	addr := os.Getenv("NIA_API_ADDR")
	if addr == "" {
		addr = ":8080"
	}

	s, err := newServer()
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
