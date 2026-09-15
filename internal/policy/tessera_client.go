package policy

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// TesseraHTTPClient implements Client against Tessera.Service's real HTTP
// surface (onboard, kill, restore, get), the thing internal/policy's own
// doc comment said would eventually replace InMemoryClient once that
// surface existed. It does now, this is that adapter.
//
// Two things about Tessera's surface shape this client, not the interface
// above, has to work around:
//
//  1. Onboard is full state reconcile, there is no incremental grant or
//     revoke endpoint. WriteGrants and DeleteGrants both do a read, then
//     a merge, then a full onboard of the merged set. That is a
//     read-modify-write over HTTP, so it has the TOCTOU problem every
//     read-modify-write has: something else can change the record between
//     the read and the write. A per-agentRef in-process mutex here
//     serializes calls made through this one client instance, which is
//     the same scope InProcessClientLock covers on Tessera's own side, a
//     single replica. It does not, and cannot, protect against a second
//     NIA replica doing the same thing at the same time. That needs a
//     shared lock (the database advisory lock Tessera's own roadmap
//     already lists for its registry) and isn't implemented here. Calling
//     it out rather than letting it pass for solved.
//
//  2. Authorization requires an HS256 JWT whose subject Tessera trusts
//     as the operator for its audit trail, and that subject can only
//     come from the token, never the request body, by Tessera's own
//     design. Kill is the one call in this interface that already carries
//     a caller-supplied operator, so Kill mints its token with that
//     operator as sub, real per-call attribution lands in Tessera's audit
//     trail. Every other call here (WriteGrants, DeleteGrants, Restore,
//     the read-only ones) has no operator parameter on the Go interface
//     to carry, so they authenticate as this client's configured system
//     subject instead. That's a real gap for Restore in particular,
//     restoring a client is exactly the kind of action an incident
//     record wants attributed to a person, not a service account, and
//     fixing it means adding an operator parameter to Client.Restore,
//     which ripples into InMemoryClient and every existing caller. Worth
//     doing, not done here.
//
//  3. Client carries no business_unit anywhere, InMemoryClient doesn't
//     model it either. WriteGrants and DeleteGrants both read whatever
//     business_unit is already on the Tessera record and pass it straight
//     back through on the merged onboard call, so it's preserved once
//     set, but there is no path through this interface to set it in the
//     first place, an agentRef onboarded through this client always gets
//     business_unit "". Setting it needs either a Client method that
//     doesn't exist yet or a caller going around this client straight to
//     Tessera's onboard endpoint.
//
//  4. Kill does not clear a client's declared grants in Tessera, only its
//     kill sentinel and its live OpenFGA tuples, confirmed against the
//     real service (tessera_client_live_test.go), not assumed from
//     reading the source. GET, and so ListGrants and Check on this
//     client, both read that declared list, not live OpenFGA state,
//     Tessera's HTTP surface has no endpoint that exposes the latter.
//     Practically: right after Kill and Restore, ListGrants still
//     reports the agent's old grants and Check against one of them still
//     returns true, even though nothing is actually authorized in
//     OpenFGA until WriteGrants runs again. WriteGrants always calls
//     onboard, even when the declared set it computes textually matches
//     what's already there, specifically to close this gap, see the
//     comment in WriteGrants itself. InMemoryClient has no such gap, its
//     Kill clears grants outright, so a caller switching between the two
//     implementations should not treat "ListGrants looks empty right
//     after a kill" as something to rely on for TesseraHTTPClient.
//
// One more thing worth knowing: mintToken signs a token good for
// defaultTokenTTL (30s) from the moment of the call, and Tessera's own
// Hs256JwtValidator applies a further 30s clock skew allowance on top of
// whatever exp it reads, so a token minted here has roughly a minute of
// slack between when it's signed and when Tessera would reject it as
// expired. That's comfortable for a single HTTP round trip; it would not
// be if this client ever started reusing one minted token across several
// calls instead of minting fresh per call, which is why it doesn't.
type TesseraHTTPClient struct {
	baseURL       string
	httpClient    *http.Client
	signingKey    []byte
	issuer        string
	audience      string
	systemSubject string
	tokenTTL      time.Duration

	mu    sync.Mutex
	locks map[string]*sync.Mutex
}

const (
	defaultTokenTTL  = 30 * time.Second
	maxResponseBytes = 1 << 20 // 1 MiB, these are small client records, a response this large means something is wrong
	minSigningKeyLen = 32      // matches Hs256JwtValidator's own minimum on the Tessera side
	toolGrantPrefix  = "tool:"
	dataGrantPrefix  = "data:"
)

// NewTesseraHTTPClient builds a Client backed by a real Tessera.Service
// instance. baseURL is the service root, for example
// "http://tessera-service:8080", no trailing slash required either way.
// signingKey is the same TESSERA_JWT_SIGNING_KEY the service was started
// with, raw bytes, not base64. systemSubject is the operator identity
// this client attributes its non-Kill calls to in Tessera's audit trail,
// see the type doc for why that's not per-caller today.
func NewTesseraHTTPClient(baseURL string, httpClient *http.Client, signingKey []byte, issuer, audience, systemSubject string) (*TesseraHTTPClient, error) {
	if strings.TrimSpace(baseURL) == "" {
		return nil, fmt.Errorf("policy: NewTesseraHTTPClient: baseURL is required")
	}
	if len(signingKey) < minSigningKeyLen {
		return nil, fmt.Errorf("policy: NewTesseraHTTPClient: signingKey must be at least %d bytes, matching Tessera's own Hs256JwtValidator minimum", minSigningKeyLen)
	}
	if strings.TrimSpace(issuer) == "" {
		return nil, fmt.Errorf("policy: NewTesseraHTTPClient: issuer is required")
	}
	if strings.TrimSpace(audience) == "" {
		return nil, fmt.Errorf("policy: NewTesseraHTTPClient: audience is required")
	}
	if strings.TrimSpace(systemSubject) == "" {
		return nil, fmt.Errorf("policy: NewTesseraHTTPClient: systemSubject is required")
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &TesseraHTTPClient{
		baseURL:       strings.TrimRight(baseURL, "/"),
		httpClient:    httpClient,
		signingKey:    signingKey,
		issuer:        issuer,
		audience:      audience,
		systemSubject: systemSubject,
		tokenTTL:      defaultTokenTTL,
		locks:         make(map[string]*sync.Mutex),
	}, nil
}

var _ Client = (*TesseraHTTPClient)(nil)

// --- wire DTOs, matching src/Tessera.Service/Endpoints/ClientOperations.cs field for field ---

type wireGrant struct {
	ApiGroup string `json:"api_group,omitempty"`
	Method   string `json:"method,omitempty"`
	Path     string `json:"path,omitempty"`
}

type onboardRequestBody struct {
	ClientRef    string      `json:"client_ref"`
	BusinessUnit string      `json:"business_unit,omitempty"`
	Grants       []wireGrant `json:"grants"`
}

type clientStateWire struct {
	ClientRef    string      `json:"client_ref"`
	BusinessUnit string      `json:"business_unit"`
	Killed       bool        `json:"killed"`
	Grants       []wireGrant `json:"grants"`
}

type onboardResultWire struct {
	Success      bool             `json:"success"`
	ErrorMessage string           `json:"error_message"`
	Warning      string           `json:"warning"`
	Client       *clientStateWire `json:"client"`
}

type killRequestBodyWire struct {
	Incident string `json:"incident"`
}

type killResultWire struct {
	Success       bool   `json:"success"`
	ErrorMessage  string `json:"error_message"`
	ClientRef     string `json:"client_ref"`
	TuplesDeleted int    `json:"tuples_deleted"`
}

type restoreResultWire struct {
	Success      bool   `json:"success"`
	ErrorMessage string `json:"error_message"`
	ClientRef    string `json:"client_ref"`
}

type getClientResultWire struct {
	Outcome      string           `json:"outcome"`
	ErrorMessage string           `json:"error_message"`
	Client       *clientStateWire `json:"client"`
}

// --- Client implementation ---

func (c *TesseraHTTPClient) WriteGrants(ctx context.Context, agentRef string, grants []Grant) error {
	lock := c.lockFor(agentRef)
	lock.Lock()
	defer lock.Unlock()

	current, found, err := c.getClientState(ctx, agentRef)
	if err != nil {
		return fmt.Errorf("policy: WriteGrants(%s): reading current state: %w", agentRef, err)
	}
	if found && current.Killed {
		return fmt.Errorf("%w: %s", ErrKilled, agentRef)
	}

	var businessUnit string
	var existing []Grant
	if found {
		businessUnit = current.BusinessUnit
		existing, err = wireGrantsToGrants(current.Grants)
		if err != nil {
			return fmt.Errorf("policy: WriteGrants(%s): decoding current grants: %w", agentRef, err)
		}
	}

	merged := existing
	for _, g := range grants {
		if !containsGrant(merged, g) {
			merged = append(merged, g)
		}
	}

	if !found && len(grants) == 0 {
		// The one case this can safely skip entirely: nothing declared
		// yet, nothing asked for, so there is nothing to create and
		// nothing to reconcile. Calling onboard here would only create a
		// phantom Tessera client record with an empty business_unit as a
		// side effect of a call that changed nothing.
		return nil
	}

	// Every other case calls onboard even when merged, textually, equals
	// what's already declared. That looks wasteful, an extra HTTP round
	// trip for what appears to be a no-op, but it is not actually a
	// no-op server side: onboard is what reconciles Tessera's live
	// OpenFGA tuples to match the declared grant list, and a kill does
	// NOT clear that declared list, only the sentinel and the live
	// tuples, confirmed against the real service, not assumed (see
	// tessera_client_live_test.go). So immediately after a restore, GET
	// still reports the old grants as declared even though nothing is
	// actually authorized in OpenFGA anymore, existing == merged in that
	// state, and skipping the onboard call there, which an earlier
	// version of this method did, would leave the agent looking granted
	// to ListGrants and Check while actually authorizing nothing. Calling
	// onboard unconditionally here is what re-applies the declared grants
	// to live state and closes that gap; it costs a round trip on every
	// call instead of only when something textually changed, that's the
	// trade being made.
	if err := c.onboardMerged(ctx, agentRef, businessUnit, merged); err != nil {
		return fmt.Errorf("policy: WriteGrants(%s): %w", agentRef, err)
	}
	return nil
}

func (c *TesseraHTTPClient) DeleteGrants(ctx context.Context, agentRef string, grants []Grant) error {
	lock := c.lockFor(agentRef)
	lock.Lock()
	defer lock.Unlock()

	current, found, err := c.getClientState(ctx, agentRef)
	if err != nil {
		return fmt.Errorf("policy: DeleteGrants(%s): reading current state: %w", agentRef, err)
	}
	if !found {
		// Nothing onboarded, nothing to delete, matches InMemoryClient's
		// DeleteGrants against an agentRef it has never seen.
		return nil
	}

	existing, err := wireGrantsToGrants(current.Grants)
	if err != nil {
		return fmt.Errorf("policy: DeleteGrants(%s): decoding current grants: %w", agentRef, err)
	}

	kept := make([]Grant, 0, len(existing))
	for _, g := range existing {
		if !containsGrant(grants, g) {
			kept = append(kept, g)
		}
	}
	if len(kept) == len(existing) {
		return nil // nothing actually changes, skip the round trip
	}

	if err := c.onboardMerged(ctx, agentRef, current.BusinessUnit, kept); err != nil {
		return fmt.Errorf("policy: DeleteGrants(%s): %w", agentRef, err)
	}
	return nil
}

func (c *TesseraHTTPClient) ListGrants(ctx context.Context, agentRef string) ([]Grant, error) {
	current, found, err := c.getClientState(ctx, agentRef)
	if err != nil {
		return nil, fmt.Errorf("policy: ListGrants(%s): %w", agentRef, err)
	}
	if !found {
		return []Grant{}, nil
	}
	grants, err := wireGrantsToGrants(current.Grants)
	if err != nil {
		return nil, fmt.Errorf("policy: ListGrants(%s): decoding grants: %w", agentRef, err)
	}
	return grants, nil
}

func (c *TesseraHTTPClient) Check(ctx context.Context, agentRef string, grant Grant) (bool, error) {
	current, found, err := c.getClientState(ctx, agentRef)
	if err != nil {
		return false, fmt.Errorf("policy: Check(%s): %w", agentRef, err)
	}
	if !found || current.Killed {
		return false, nil
	}
	grants, err := wireGrantsToGrants(current.Grants)
	if err != nil {
		return false, fmt.Errorf("policy: Check(%s): decoding grants: %w", agentRef, err)
	}
	return containsGrant(grants, grant), nil
}

func (c *TesseraHTTPClient) Kill(ctx context.Context, agentRef, incident, operator string) (KillResult, error) {
	lock := c.lockFor(agentRef)
	lock.Lock()
	defer lock.Unlock()

	if strings.TrimSpace(operator) == "" {
		return KillResult{}, fmt.Errorf("policy: Kill(%s): operator is required, Tessera attributes the kill to whatever subject signs the request", agentRef)
	}

	var result killResultWire
	status, raw, err := c.do(ctx, http.MethodPost, "/clients/"+url.PathEscape(agentRef)+"/kill", operator, killRequestBodyWire{Incident: incident}, &result)
	if err != nil {
		return KillResult{}, fmt.Errorf("policy: Kill(%s): %w", agentRef, err)
	}
	if status != http.StatusOK || !result.Success {
		return KillResult{}, fmt.Errorf("policy: Kill(%s): tessera returned status %d: %s", agentRef, status, firstNonEmpty(result.ErrorMessage, string(raw)))
	}
	return KillResult{AgentRef: result.ClientRef, TuplesDeleted: result.TuplesDeleted}, nil
}

func (c *TesseraHTTPClient) Restore(ctx context.Context, agentRef string) error {
	lock := c.lockFor(agentRef)
	lock.Lock()
	defer lock.Unlock()

	var result restoreResultWire
	status, raw, err := c.do(ctx, http.MethodPost, "/clients/"+url.PathEscape(agentRef)+"/restore", c.systemSubject, nil, &result)
	if err != nil {
		return fmt.Errorf("policy: Restore(%s): %w", agentRef, err)
	}
	if status != http.StatusOK || !result.Success {
		return fmt.Errorf("policy: Restore(%s): tessera returned status %d: %s", agentRef, status, firstNonEmpty(result.ErrorMessage, string(raw)))
	}
	return nil
}

func (c *TesseraHTTPClient) IsKilled(ctx context.Context, agentRef string) (bool, error) {
	current, found, err := c.getClientState(ctx, agentRef)
	if err != nil {
		return false, fmt.Errorf("policy: IsKilled(%s): %w", agentRef, err)
	}
	if !found {
		return false, nil
	}
	return current.Killed, nil
}

// --- shared plumbing ---

// onboardMerged calls onboard with a full grant set already computed by
// the caller (WriteGrants or DeleteGrants) and turns Tessera's warning
// for a killed client into ErrKilled, rather than reporting success for a
// write that didn't actually apply. Reaching that warning here means the
// agent was killed between this client's read and this write, the race
// the type doc describes, everything up to this point already checked
// Killed on the value it read.
func (c *TesseraHTTPClient) onboardMerged(ctx context.Context, agentRef, businessUnit string, grants []Grant) error {
	wireGrants, err := grantsToWireGrants(grants)
	if err != nil {
		return fmt.Errorf("encoding grants: %w", err)
	}

	var result onboardResultWire
	status, raw, err := c.do(ctx, http.MethodPost, "/clients/onboard", c.systemSubject, onboardRequestBody{
		ClientRef:    agentRef,
		BusinessUnit: businessUnit,
		Grants:       wireGrants,
	}, &result)
	if err != nil {
		return err
	}
	if status != http.StatusOK || !result.Success {
		return fmt.Errorf("tessera onboard returned status %d: %s", status, firstNonEmpty(result.ErrorMessage, string(raw)))
	}
	if result.Warning != "" {
		return fmt.Errorf("%w: %s (killed concurrently with this write)", ErrKilled, agentRef)
	}
	return nil
}

func (c *TesseraHTTPClient) getClientState(ctx context.Context, agentRef string) (*clientStateWire, bool, error) {
	var result getClientResultWire
	status, raw, err := c.do(ctx, http.MethodGet, "/clients/"+url.PathEscape(agentRef), c.systemSubject, nil, &result)
	if err != nil {
		return nil, false, err
	}
	switch status {
	case http.StatusOK:
		if result.Client == nil {
			return nil, false, fmt.Errorf("tessera returned a found client with no client body")
		}
		return result.Client, true, nil
	case http.StatusNotFound:
		return nil, false, nil
	case http.StatusBadRequest:
		return nil, false, fmt.Errorf("invalid client_ref %q: %s", agentRef, firstNonEmpty(result.ErrorMessage, string(raw)))
	default:
		return nil, false, fmt.Errorf("unexpected status %d: %s", status, string(raw))
	}
}

// do sends one request to Tessera, mints a fresh short-lived token for
// every call rather than reusing one, minting is cheap (one HMAC) and it
// keeps a long-lived process from ever presenting an expired token. It
// returns the raw response body alongside the decoded one so callers can
// put real detail in an error message on a status code they didn't
// expect, rather than "something went wrong."
func (c *TesseraHTTPClient) do(ctx context.Context, method, path, subject string, reqBody, out any) (status int, raw []byte, err error) {
	var bodyReader io.Reader
	if reqBody != nil {
		b, marshalErr := json.Marshal(reqBody)
		if marshalErr != nil {
			return 0, nil, fmt.Errorf("encoding request body: %w", marshalErr)
		}
		bodyReader = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return 0, nil, fmt.Errorf("building request: %w", err)
	}
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	token, err := c.mintToken(subject)
	if err != nil {
		return 0, nil, fmt.Errorf("minting request token: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		// Network failure, timeout, or context cancellation, propagated
		// as-is (wrapped, not swallowed): a read-modify-write caller has
		// to know a step didn't happen, a false "nothing changed" here
		// would be worse than an error.
		return 0, nil, fmt.Errorf("calling tessera %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	raw, err = io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf("reading tessera response body: %w", err)
	}

	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return resp.StatusCode, raw, fmt.Errorf("decoding tessera response (status %d): %w", resp.StatusCode, err)
		}
	}
	return resp.StatusCode, raw, nil
}

type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

type jwtPayload struct {
	Iss string `json:"iss"`
	Aud string `json:"aud"`
	Sub string `json:"sub"`
	Exp int64  `json:"exp"`
}

// mintToken signs an HS256 JWT the same way Tessera's own
// Hs256JwtValidator checks one, hand-rolled here for the same reason it's
// hand-rolled there: this is a shared-secret HS256 token, small enough to
// own directly without pulling in a JWT library for four fields.
func (c *TesseraHTTPClient) mintToken(subject string) (string, error) {
	if strings.TrimSpace(subject) == "" {
		return "", fmt.Errorf("cannot mint a tessera token with an empty subject")
	}

	header, err := json.Marshal(jwtHeader{Alg: "HS256", Typ: "JWT"})
	if err != nil {
		return "", fmt.Errorf("encoding jwt header: %w", err)
	}
	payload, err := json.Marshal(jwtPayload{
		Iss: c.issuer,
		Aud: c.audience,
		Sub: subject,
		Exp: time.Now().Add(c.tokenTTL).Unix(),
	})
	if err != nil {
		return "", fmt.Errorf("encoding jwt payload: %w", err)
	}

	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, c.signingKey)
	mac.Write([]byte(signingInput))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return signingInput + "." + signature, nil
}

func (c *TesseraHTTPClient) lockFor(agentRef string) *sync.Mutex {
	c.mu.Lock()
	defer c.mu.Unlock()
	l, ok := c.locks[agentRef]
	if !ok {
		// Never evicted, same tradeoff Tessera's own InProcessClientLock
		// makes with its ConcurrentDictionary<string, SemaphoreSlim>, one
		// mutex per distinct agentRef ever seen, for the lifetime of the
		// process. Fine at NIA's expected agent-population scale, would
		// need revisiting for a deployment with a very high cardinality
		// or constantly churning set of agentRefs.
		l = &sync.Mutex{}
		c.locks[agentRef] = l
	}
	return l
}

func grantsToWireGrants(grants []Grant) ([]wireGrant, error) {
	out := make([]wireGrant, 0, len(grants))
	for _, g := range grants {
		switch g.Kind {
		case "api_group":
			if g.Group == "" {
				return nil, fmt.Errorf("api_group grant has an empty group")
			}
			// An api_group named literally "tool:x" or "data:x" would
			// come back from wireGrantsToGrants misread as a tool or
			// data grant, that function has no way to tell "a real
			// api_group that happens to start with the same prefix"
			// apart from "a tool grant encoded that way", it always
			// prefers the more specific case. Reject it here instead of
			// silently reclassifying the grant on the way back.
			if strings.HasPrefix(g.Group, toolGrantPrefix) || strings.HasPrefix(g.Group, dataGrantPrefix) {
				return nil, fmt.Errorf("api_group %q collides with this client's tool/data grant encoding (the %q and %q prefixes), rename the group", g.Group, toolGrantPrefix, dataGrantPrefix)
			}
			out = append(out, wireGrant{ApiGroup: g.Group})
		case "endpoint":
			if g.Method == "" || g.Path == "" {
				return nil, fmt.Errorf("endpoint grant needs both method and path")
			}
			out = append(out, wireGrant{Method: g.Method, Path: g.Path})
		case "tool":
			// Tessera's wire format has no field for "this is a tool, not
			// an api_group", ApiGroup is just an opaque string as far as
			// Tessera and OpenFGA are concerned, api_group:{group} is the
			// object id and Tessera never inspects the value beyond that.
			// Prefixing it is NIA's own convention for reusing that one
			// field for the two extra grant kinds NIA has and Tessera
			// doesn't, not a change to Tessera's protocol.
			if g.Object == "" {
				return nil, fmt.Errorf("tool grant has an empty object")
			}
			out = append(out, wireGrant{ApiGroup: toolGrantPrefix + g.Object})
		case "data":
			if g.Object == "" {
				return nil, fmt.Errorf("data grant has an empty object")
			}
			out = append(out, wireGrant{ApiGroup: dataGrantPrefix + g.Object})
		default:
			return nil, fmt.Errorf("unknown grant kind %q", g.Kind)
		}
	}
	return out, nil
}

func wireGrantsToGrants(wire []wireGrant) ([]Grant, error) {
	out := make([]Grant, 0, len(wire))
	for _, w := range wire {
		switch {
		case w.Method != "" && w.Path != "":
			out = append(out, GrantForEndpoint(w.Method, w.Path))
		case strings.HasPrefix(w.ApiGroup, toolGrantPrefix):
			out = append(out, GrantForTool(strings.TrimPrefix(w.ApiGroup, toolGrantPrefix)))
		case strings.HasPrefix(w.ApiGroup, dataGrantPrefix):
			out = append(out, GrantForData(strings.TrimPrefix(w.ApiGroup, dataGrantPrefix)))
		case w.ApiGroup != "":
			out = append(out, GrantForAPIGroup(w.ApiGroup))
		default:
			return nil, fmt.Errorf("tessera returned a grant with neither api_group nor method and path set")
		}
	}
	return out, nil
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
