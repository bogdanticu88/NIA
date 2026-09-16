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
	"time"

	"github.com/bogdanticu88/nia/internal/audit"
	"github.com/bogdanticu88/nia/internal/credentials"
	"github.com/bogdanticu88/nia/internal/graph"
	"github.com/bogdanticu88/nia/internal/identity"
	"github.com/bogdanticu88/nia/internal/policy"
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
	// Same NIA_SENSITIVITY_RULES_PATH env var cmd/gateway reads, unset
	// means every resource classifies as Public, so a blast-radius query
	// still returns its node counts, it just can't say which reachable
	// data resources are the sensitive or critical ones.
	sensitive, err := sensitivity.FromEnvClassifier()
	if err != nil {
		return nil, fmt.Errorf("nia-api: %w", err)
	}
	return &server{
		agents:    registry.NewInMemoryAgentRegistry(),
		toolCat:   tools.NewInMemoryCatalog(),
		creds:     credentials.NewInMemoryStore(),
		pol:       pol,
		auditLog:  auditLog,
		graph:     graph.NewInMemoryGraph(),
		sensitive: sensitive,
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
	s.graphAddNode(ctx, agent.Ref, graph.NodeAgent)
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
	s.graphAddNode(ctx, cred.ID, graph.NodeCredential)
	s.graphAddEdge(ctx, cred.ID, ref, graph.EdgeBoundTo)
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
		niahttp.WriteError(w, http.StatusConflict, err.Error())
		return
	}
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
			niahttp.WriteError(w, http.StatusConflict, "agent is killed, restore before writing grants")
			return
		}
		niahttp.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.graphAddGrantEdges(ctx, ref, grants)
	s.audit(ctx, audit.Event{
		Action:   "grant.written",
		AgentRef: ref,
		Operator: req.Operator,
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
		niahttp.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(ctx, audit.Event{
		Action:   "grant.deleted",
		AgentRef: ref,
		Operator: req.Operator,
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
// kept separate.
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
		log.Printf("nia-api: graph add node failed: %v", err)
	}
}

func (s *server) graphAddEdge(ctx context.Context, from, to string, kind graph.EdgeKind) {
	if err := s.graph.AddEdge(ctx, graph.Edge{From: from, To: to, Kind: kind}); err != nil {
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
// Known gap, documented rather than silently wrong: handleDeleteGrants
// does not call the mirror of this, internal/graph.Graph has no edge
// removal primitive today, so a revoked grant still shows up as a
// reachable edge in a blast-radius query until something adds one. An
// operator relying on the graph for an exact, current picture after a
// revoke should still check internal/policy's own ListGrants, the
// graph is a superset, not a stale-safe mirror, until this is fixed.
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

func (s *server) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("POST /agents", s.handleRegisterAgent)
	mux.HandleFunc("GET /agents", s.handleListAgents)
	mux.HandleFunc("POST /policy/kill", s.handleKill)
	mux.HandleFunc("POST /agents/{ref}/grants", s.handleWriteGrants)
	mux.HandleFunc("DELETE /agents/{ref}/grants", s.handleDeleteGrants)
	mux.HandleFunc("GET /agents/{ref}/grants", s.handleListGrants)
	mux.HandleFunc("POST /agents/{ref}/credentials", s.handleIssueCredential)
	mux.HandleFunc("GET /agents/{ref}/credentials", s.handleListCredentials)
	mux.HandleFunc("POST /credentials/{id}/revoke", s.handleRevokeCredential)
	mux.HandleFunc("POST /tools", s.handleRegisterTool)
	mux.HandleFunc("GET /tools", s.handleListTools)
	mux.HandleFunc("GET /tools/{name}", s.handleGetTool)
	mux.HandleFunc("GET /audit", s.handleRecentAudit)
	mux.HandleFunc("GET /agents/{ref}/audit", s.handleAgentAudit)
	mux.HandleFunc("POST /graph/nodes", s.handleAddGraphNode)
	mux.HandleFunc("POST /graph/edges", s.handleAddGraphEdge)
	mux.HandleFunc("GET /graph/{id}/neighbors", s.handleGraphNeighbors)
	mux.HandleFunc("GET /graph/{id}/reachable", s.handleGraphReachable)
	mux.HandleFunc("GET /graph/{id}/blast-radius", s.handleBlastRadius)
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
