// Package identity defines the canonical shape of a non-human identity
// (NHI) inside NIA: agents, service accounts, and anything else that isn't
// a human but needs to be known, granted permissions, and killed.
//
// This follows the shape of Tessera's ClientRef / Assurance /
// ResolvedClient trio (see Tessera.ControlPlane/Model.cs). An AgentRef
// here is what a ClientRef is there, generalized from "M2M API client"
// to "agent."
package identity

import (
	"context"
	"crypto/x509"
	"time"
)

// Assurance is how confident NIA is in an identity resolution. Gate
// high-value operations (credential issuance, delegation grants, kill
// switch overrides) on Strong. Same three levels Tessera uses, so a
// resolution can be handed straight to the policy client without
// translation.
type Assurance int

const (
	AssuranceWeak Assurance = iota
	AssuranceMedium
	AssuranceStrong
)

func (a Assurance) String() string {
	switch a {
	case AssuranceStrong:
		return "strong"
	case AssuranceMedium:
		return "medium"
	default:
		return "weak"
	}
}

// LifecycleState is where an agent identity sits in its own lifecycle.
// Killed is distinct from Suspended: a suspension is expected to be
// lifted, a kill is an incident response action and requires an explicit
// Restore through the policy client.
type LifecycleState string

const (
	StateActive    LifecycleState = "active"
	StateSuspended LifecycleState = "suspended"
	StateKilled    LifecycleState = "killed"
)

// AgentRef is the canonical, stable reference for one non-human identity.
// Whatever the gateway or control-plane API saw when a request came in
// (an API key, a JWT subject, an mTLS thumbprint) resolves to exactly one
// of these. This is the identity the whole rest of the system, policy,
// credentials, audit, risk, graph, keys off.
type AgentRef struct {
	Ref          string // canonical id, e.g. "agent:billing-reconciler"
	DisplayName  string
	Owner        string // human or team accountable for this agent
	BusinessUnit string
	Assurance    Assurance
	State        LifecycleState
	Purpose      string // free-text: what this agent is for, reviewed at onboarding
	RegisteredAt time.Time
	KillIncident string // set only when State == StateKilled
	KilledAt     *time.Time
	KilledBy     string
}

// ResolveContext is what the gateway handed to identity resolution: raw
// claims and headers off the inbound request. Same shape as Tessera's
// ResolveContext, so an IdentityResolver implementation can reuse the
// same normalization logic Tessera's canonical-form code already proved
// out (see Tessera.ControlPlane/CanonicalForm.cs).
type ResolveContext struct {
	Claims  map[string]string
	Headers map[string]string

	// VerifiedChains is what the TLS stack concluded about the client
	// certificate, if one was presented: the chains it successfully
	// built to a configured trusted root, leaf first. Empty when the
	// connection is plain HTTP, when no client certificate was offered,
	// or when one was offered and failed verification, because the TLS
	// handshake fails in that last case and the request never arrives.
	//
	// This carries the certificate itself rather than a thumbprint on
	// purpose. A resolver that took a precomputed thumbprint would be
	// trusting whoever computed it, and the entire security property of
	// certificate authentication is that the identity comes from the key
	// the peer proved it holds during the handshake, not from anything
	// the peer can assert. Every caller that needs a thumbprint computes
	// it here, from these bytes.
	VerifiedChains [][]*x509.Certificate
}

// LeafCertificate returns the verified leaf certificate, the one the
// peer actually presented, or nil when no client certificate was
// verified on this connection.
func (rc ResolveContext) LeafCertificate() *x509.Certificate {
	if len(rc.VerifiedChains) == 0 || len(rc.VerifiedChains[0]) == 0 {
		return nil
	}
	return rc.VerifiedChains[0][0]
}

// ResolvedIdentity is the outcome of resolving a request to an AgentRef.
// CredentialID is set when a real credential authenticated this
// request (see cmd/gateway/authn.go's credentialResolver), empty for
// anything that isn't credential-backed. It exists so a caller further
// down the chain, internal/audit, internal/monitoring, can attribute a
// specific request to the specific credential that authenticated it,
// something the pre-hardening headerResolver had no way to do at all,
// see internal/monitoring.Monitor.revokeCredentials's own doc comment
// on the coarser "revoke everything" behavior that gap used to force.
type ResolvedIdentity struct {
	Ref          string
	Assurance    Assurance
	CredentialID string
}

// Resolver maps an inbound request to a canonical AgentRef. The gateway
// calls this before it ever asks the policy client for an authorization
// decision. Resolve returning (nil, nil) means "no identity could be
// established, and that's not itself an error," the caller treats it
// as unauthenticated (401); Resolve returning a non-nil error means
// something needed to answer the question failed (a credential store
// or policy client unreachable), the caller must not treat that as
// "unauthenticated," see cmd/gateway's handleToolCall, an authentication
// infrastructure failure fails closed (500), it is never silently
// treated as "let it through" or quietly downgraded to a plain
// unresolved identity.
type Resolver interface {
	Resolve(ctx context.Context, rc ResolveContext) (*ResolvedIdentity, error)
}
