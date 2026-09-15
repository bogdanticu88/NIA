// Package credentials owns the credential lifecycle for a non-human
// identity: issuance, rotation, and revocation. This is explicitly
// something Tessera does not do; Tessera's IIdentityResolver assumes a
// credential already exists and only resolves it to a canonical
// AgentRef. NIA needs to actually mint and retire the credentials
// Tessera later resolves.
//
// Revocation here is a smaller action than the kill switch in
// internal/policy: revoking a credential retires one key without
// touching the agent's grants or identity. Killing an agent (see
// internal/policy.Client.Kill) is the bigger hammer, use it when the
// agent itself is compromised, not just one leaked key.
package credentials

import (
	"context"
	"errors"
	"time"
)

// Kind is the credential type. NIA doesn't generate cryptographic
// material itself in this scaffold; issuance below returns a reference
// and metadata for the real secret to be minted against by whatever
// secrets backend the deployment uses (Vault, cloud KMS, etc).
type Kind string

const (
	KindAPIKey     Kind = "api_key"
	KindOAuthToken Kind = "oauth_token"
	KindMTLSCert   Kind = "mtls_cert"
)

// Status is where a credential sits in its own lifecycle.
type Status string

const (
	StatusActive  Status = "active"
	StatusExpired Status = "expired"
	StatusRevoked Status = "revoked"
)

// Credential is metadata about one issued credential. The credential
// material itself never lives here, only what's needed to know it
// exists, who it belongs to, and whether it's still good.
type Credential struct {
	ID        string
	AgentRef  string
	Kind      Kind
	Status    Status
	IssuedAt  time.Time
	ExpiresAt *time.Time
	RevokedAt *time.Time
	RevokedBy string
	Reason    string
}

var ErrNotFound = errors.New("credentials: not found")

// Store is where credential metadata lives. A production deployment
// backs this with Postgres; the in-memory implementation below is the
// reference used for local dev, same as every other package here.
type Store interface {
	Issue(ctx context.Context, agentRef string, kind Kind, ttl time.Duration) (Credential, error)
	Get(ctx context.Context, id string) (Credential, error)
	ListForAgent(ctx context.Context, agentRef string) ([]Credential, error)
	Revoke(ctx context.Context, id, revokedBy, reason string) error
}
