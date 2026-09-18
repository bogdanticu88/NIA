package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// OpenFGAChecker answers Check by asking OpenFGA directly, and delegates
// every other Client method to a base Client (in practice
// TesseraHTTPClient). It exists because of a real fail-open in the way
// Check used to be answered.
//
// TesseraHTTPClient.Check reads Tessera's GET /clients/{ref} and looks
// for the grant in the *declared* grant list that comes back. Tessera's
// HTTP surface has no endpoint that exposes live OpenFGA state, so that
// declared list is the only thing it can read, and the two genuinely
// diverge: Kill deletes a client's OpenFGA tuples but leaves its
// declared grants in place, and Restore clears the kill sentinel
// without rewriting them. Between a Restore and the next WriteGrants,
// TesseraHTTPClient.Check returns true for grants that have no tuples
// backing them at all, and the gateway allows a call nothing has
// actually authorized. See TesseraHTTPClient's own doc comment, point 4,
// which documents the divergence but could not fix it from inside that
// client.
//
// This asks the authorization store itself. An allow here means a tuple
// exists right now, which is the only thing "is this authorized" can
// honestly mean.
//
// What this deliberately does not do: writes. WriteGrants, DeleteGrants,
// Kill and Restore all still go through the base client, so Tessera
// remains the single writer and the reconcile, sentinel-first kill, and
// audit trail it owns stay exactly where they are. Reads that need
// Tessera's own bookkeeping rather than the tuple store, ListGrants (the
// declared set, which is genuinely a different question from "what is
// live") and IsKilled (the sentinel lives in Tessera's registry, not in
// OpenFGA, see KillSwitchService), also stay on the base client. This
// type changes exactly one thing: where a hot-path authorization
// decision gets its answer.
type OpenFGAChecker struct {
	base    Client
	httpC   *http.Client
	baseURL string
	storeID string
	modelID string // optional, empty means OpenFGA uses the store's latest model
}

// NewOpenFGAChecker wraps base so its Check calls go to the OpenFGA
// instance at baseURL for storeID. modelID may be empty, in which case
// OpenFGA evaluates against the store's most recent authorization
// model, the same default Tessera's own store uses when it isn't
// configured with one.
func NewOpenFGAChecker(base Client, baseURL, storeID, modelID string) *OpenFGAChecker {
	return &OpenFGAChecker{
		base:    base,
		httpC:   &http.Client{Timeout: 10 * time.Second},
		baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		storeID: strings.TrimSpace(storeID),
		modelID: strings.TrimSpace(modelID),
	}
}

func (c *OpenFGAChecker) WriteGrants(ctx context.Context, agentRef string, grants []Grant) error {
	return c.base.WriteGrants(ctx, agentRef, grants)
}

func (c *OpenFGAChecker) DeleteGrants(ctx context.Context, agentRef string, grants []Grant) error {
	return c.base.DeleteGrants(ctx, agentRef, grants)
}

func (c *OpenFGAChecker) ListGrants(ctx context.Context, agentRef string) ([]Grant, error) {
	return c.base.ListGrants(ctx, agentRef)
}

func (c *OpenFGAChecker) Kill(ctx context.Context, agentRef, incident, operator string) (KillResult, error) {
	return c.base.Kill(ctx, agentRef, incident, operator)
}

func (c *OpenFGAChecker) Restore(ctx context.Context, agentRef, operator string) error {
	return c.base.Restore(ctx, agentRef, operator)
}

func (c *OpenFGAChecker) SetBusinessUnit(ctx context.Context, agentRef, businessUnit string) error {
	return c.base.SetBusinessUnit(ctx, agentRef, businessUnit)
}

func (c *OpenFGAChecker) IsKilled(ctx context.Context, agentRef string) (bool, error) {
	return c.base.IsKilled(ctx, agentRef)
}

// checkRequestWire and checkResponseWire are OpenFGA's own /check shape.
// Field names are what OpenFGA accepts on the wire, not Go convention.
type checkRequestWire struct {
	TupleKey             checkTupleKeyWire `json:"tuple_key"`
	AuthorizationModelID string            `json:"authorization_model_id,omitempty"`
}

type checkTupleKeyWire struct {
	User     string `json:"user"`
	Relation string `json:"relation"`
	Object   string `json:"object"`
}

type checkResponseWire struct {
	Allowed bool `json:"allowed"`
}

// Check asks OpenFGA whether the tuple backing this grant exists right
// now. A failure to reach OpenFGA is an error, never a false: the
// gateway turns a Check error into a 500, not a denial and never an
// allow, see cmd/gateway's handleToolCall.
func (c *OpenFGAChecker) Check(ctx context.Context, agentRef string, grant Grant) (bool, error) {
	relation, object, err := grantToTuple(grant)
	if err != nil {
		return false, fmt.Errorf("policy: Check(%s): %w", agentRef, err)
	}

	body, err := json.Marshal(checkRequestWire{
		TupleKey: checkTupleKeyWire{
			User:     "client:" + canonicalClientRef(agentRef),
			Relation: relation,
			Object:   object,
		},
		AuthorizationModelID: c.modelID,
	})
	if err != nil {
		return false, fmt.Errorf("policy: Check(%s): encoding request: %w", agentRef, err)
	}

	url := fmt.Sprintf("%s/stores/%s/check", c.baseURL, c.storeID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return false, fmt.Errorf("policy: Check(%s): building request: %w", agentRef, err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpC.Do(req)
	if err != nil {
		return false, fmt.Errorf("policy: Check(%s): openfga unreachable: %w", agentRef, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return false, fmt.Errorf("policy: Check(%s): reading response: %w", agentRef, err)
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("policy: Check(%s): openfga returned status %d: %s", agentRef, resp.StatusCode, strings.TrimSpace(string(raw)))
	}

	var decoded checkResponseWire
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return false, fmt.Errorf("policy: Check(%s): decoding response: %w", agentRef, err)
	}
	return decoded.Allowed, nil
}

// canonicalClientRef is the exact string Tessera stores a client under,
// reproduced here because a Check has to name the same OpenFGA user
// Tessera's own writes named. Two transformations, in this order:
// NIA's own escape for ':' (encodeClientRef, because Tessera's
// CanonicalForm.ClientRef rejects that character outright, see
// TesseraHTTPClient's doc comment point 5), then the trim and
// lowercase CanonicalForm.ClientRef itself applies.
//
// This is duplicated knowledge about another service's canonical form,
// which is a real cost worth naming: if Tessera ever changes how it
// canonicalizes a client_ref, every Check through this client silently
// starts asking about a user that doesn't exist, and a silent "no tuple
// found" reads as a denial rather than an error. The live test against
// a real Tessera plus a real OpenFGA is what would catch that, which is
// why it exists rather than only a fake-server test.
func canonicalClientRef(agentRef string) string {
	return strings.ToLower(strings.TrimSpace(encodeClientRef(agentRef)))
}

// grantToTuple maps one Grant to the (relation, object) pair Tessera's
// GrantTupleMapper writes for it. Kept deliberately close to that
// mapper's own shape: an api_group grant becomes member on
// api_group:{group}, and NIA's two extra kinds ride the same relation
// with their prefixed object names, which is the same encoding
// grantsToWire already uses on the write side of this package.
//
// An endpoint grant is not supported here and returns an error rather
// than a guess. Tessera canonicalizes an endpoint path against a
// declared endpoint catalog (CanonicalForm.Path collapses path
// parameters to {param} at catalog positions), and NIA has no copy of
// that catalog, so the object name this would have to construct is not
// derivable from the grant alone. Nothing in NIA checks an endpoint
// grant today, cmd/gateway only ever calls GrantForTool and
// GrantForData, so this is a real but currently unreachable limitation.
// Failing loudly is the right shape for it: a wrong object name would
// come back "not allowed" and be indistinguishable from a genuine
// denial.
func grantToTuple(grant Grant) (relation, object string, err error) {
	lower := func(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
	switch grant.Kind {
	case "api_group":
		if grant.Group == "" {
			return "", "", fmt.Errorf("api_group grant has an empty group")
		}
		return "member", "api_group:" + lower(grant.Group), nil
	case "tool":
		if grant.Object == "" {
			return "", "", fmt.Errorf("tool grant has an empty object")
		}
		return grantedRelation, toolObjectType + ":" + lower(grant.Object), nil
	case "data":
		if grant.Object == "" {
			return "", "", fmt.Errorf("data grant has an empty object")
		}
		return grantedRelation, dataObjectType + ":" + lower(grant.Object), nil
	case "endpoint":
		return "", "", fmt.Errorf("endpoint grants cannot be checked directly against OpenFGA from NIA: Tessera canonicalizes the path against its endpoint catalog, which this process has no copy of")
	default:
		return "", "", fmt.Errorf("unknown grant kind %q", grant.Kind)
	}
}

var _ Client = (*OpenFGAChecker)(nil)
