package main

import (
	"context"
	"strings"

	"github.com/bogdanticu88/nia/internal/credentials"
	"github.com/bogdanticu88/nia/internal/identity"
	"github.com/bogdanticu88/nia/internal/policy"
)

// bearerPrefix is the scheme name an inbound Authorization header must
// use. A credential presented any other way, no header, a different
// scheme, a malformed value, resolves to (nil, nil): no identity
// established, not an error, same "unresolved" signal handleToolCall
// already turns into a 401, see identity.Resolver's own doc comment on
// why that distinction matters.
const bearerPrefix = "Bearer "

// credentialResolver is the real identity.Resolver this security
// hardening pass adds: Agent -> Credential -> Authentication ->
// Authenticated Agent Identity -> Authorization, replacing
// headerResolver's unauthenticated X-Agent-Ref trust as the gateway's
// default. A caller presents "Authorization: Bearer <credential-id>.
// <secret>"; the id half is how Verify finds the row without scanning
// the whole store, the secret half is the actual proof of possession,
// see internal/credentials' package doc comment for the full format
// and why a fast hash is the right call here.
//
// Three things happen here that headerResolver could never do:
//  1. The secret is actually checked against a stored digest
//     (credentials.Store.Verify), not just an identifier taken at face
//     value.
//  2. Verify itself already refuses a revoked, expired, or disabled
//     credential, see credentials.Credential.Effective, so those three
//     states have real authentication consequences, not just a status
//     field nobody reads.
//  3. A credential belonging to a killed agent is refused here too, a
//     second, independent check against the same policy.Client the
//     authorization step below also consults, defense in depth: even
//     if a deployment somehow has a stale credentials.Store that still
//     thinks a credential is active, an agent that's been killed
//     cannot authenticate through this resolver, closing the specific
//     gap the security hardening directive named directly. See
//     policy.Client.IsKilled's own doc comment for why this is the
//     genuinely shared, multi-process source of truth once pointed at
//     a real Tessera instance rather than each process's own
//     in-memory default, docs/ARCHITECTURE.md's "State convergence"
//     section has the full reasoning.
type credentialResolver struct {
	creds credentials.Store
	pol   policy.Client
}

func (c credentialResolver) Resolve(ctx context.Context, rc identity.ResolveContext) (*identity.ResolvedIdentity, error) {
	raw, ok := rc.Headers["Authorization"]
	if !ok || raw == "" {
		return nil, nil
	}
	if !strings.HasPrefix(raw, bearerPrefix) {
		return nil, nil
	}
	token := strings.TrimPrefix(raw, bearerPrefix)
	id, secret, ok := strings.Cut(token, ".")
	if !ok || id == "" || secret == "" {
		return nil, nil
	}

	cred, err := c.creds.Verify(ctx, id, secret)
	if err != nil {
		if err == credentials.ErrInvalidCredential {
			// Wrong secret, unknown id, revoked, expired, disabled: all
			// of them collapse to "no identity," not an error, same
			// reasoning credentials.ErrInvalidCredential's own doc
			// comment gives for not distinguishing them to the caller.
			return nil, nil
		}
		// The store itself failed to answer (unreachable database,
		// say). This is not "no identity," it's "we couldn't tell,"
		// and it must not be treated as either an allow or a plain
		// unresolved 401, see identity.Resolver's own doc comment: a
		// verification infrastructure failure fails closed, the
		// caller (handleToolCall) turns this into a 500, never a free
		// pass.
		return nil, err
	}

	killed, err := c.pol.IsKilled(ctx, cred.AgentRef)
	if err != nil {
		// Same fail-closed reasoning: if the authoritative kill state
		// can't be confirmed, this is not a successful authentication.
		return nil, err
	}
	if killed {
		// "A credential belonging to a killed agent must not
		// authenticate," stated directly in the security hardening
		// directive. Also treated as a plain unresolved identity
		// rather than a distinguishable error, an attacker probing
		// whether a specific agent is killed by watching for a
		// different failure mode here is exactly the kind of oracle
		// this collapses away, same reasoning as the Verify branch
		// above.
		return nil, nil
	}

	return &identity.ResolvedIdentity{
		Ref:          cred.AgentRef,
		Assurance:    identity.AssuranceStrong,
		CredentialID: cred.ID,
	}, nil
}

var _ identity.Resolver = credentialResolver{}
