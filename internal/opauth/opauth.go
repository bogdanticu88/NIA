// Package opauth authenticates the human or system callers of
// cmd/api's own HTTP surface, the control plane an operator drives
// through niactl or a script.
//
// This is a different problem from internal/credentials: that package
// authenticates an agent (an NHI) to cmd/gateway's hot path, this one
// authenticates whoever is allowed to register agents, write grants,
// pull the kill switch, and read the audit trail in the first place,
// and, as of roles.go, decides which of those each caller may do.
// Before this package existed, cmd/api trusted whatever "operator"
// string a caller put in a request body, register an agent as
// "owner":"bogdan" and kill it as "operator":"bogdan" and the API
// believed both, no proof required, see the security hardening
// directive's own audit findings. This package closes both halves of
// that: authentication, a verified caller identity rather than a
// claimed one, and authorization, which of cmd/api's actions that
// identity may take, see roles.go. Authorization came later than
// authentication and the gap in between was real: for a while any
// token that authenticated could kill any agent.
package opauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"
)

// Operator is an authenticated caller of cmd/api. Name is whatever the
// token was labeled with at issuance, an operator's own name or a
// service account's, used for the audit trail and for *_by /
// operator fields instead of trusting whatever the request body
// claims, see cmd/api/opauth.go's operatorFromContext.
type Operator struct {
	Name string
	// Roles is what this operator is allowed to do, see roles.go. Empty
	// means nothing is allowed, which is the safe direction for a value
	// that failed to load: a handler asks Can(perm) and gets false
	// rather than a permissive default.
	Roles []Role
	// ExpiresAt, when set, is when this token stops authenticating.
	// Checked at Verify time against the clock rather than swept in the
	// background, the same choice internal/credentials.Credential.
	// Effective makes and for the same reason: nothing has to be
	// running for an expired token to stop working.
	ExpiresAt *time.Time
}

// Expired reports whether this operator's token is past its expiry at
// now. An operator with no expiry never expires.
func (o Operator) Expired(now time.Time) bool {
	return o.ExpiresAt != nil && !now.Before(*o.ExpiresAt)
}

// ErrInvalidToken covers every reason a presented token fails: unknown,
// malformed, or (this package has no revocation or expiry today, see
// Store's doc comment) simply wrong. Collapsed to one error on purpose,
// the same reasoning internal/credentials.ErrInvalidCredential's doc
// comment gives: a caller probing which specific reason a token failed
// gets no signal to work with.
var ErrInvalidToken = errors.New("opauth: invalid token")

// Store verifies a presented bearer token and returns the Operator it
// belongs to. This is deliberately the simplest thing that's actually
// real: a fixed, admin-managed list of tokens loaded at startup (see
// StaticStore and FromEnv), not a database, not an external identity
// provider, not OAuth. NIA doesn't have enough distinct human callers
// yet to justify more, and a static list that's actually checked beats
// a more sophisticated design that never gets built. What this
// deliberately doesn't have: issuance. There is no endpoint that mints
// an operator token, they are written into the file by whoever
// administers the deployment. Expiry and revocation it does have, see
// Operator.ExpiresAt and ReloadingStore: a token can carry an
// expires_at, and removing a line from the file retires that token on
// every process reading it within a couple of seconds, no restart.
//
// Per-operator scoping used to be on that list and is not any more, see
// roles.go: a token declares roles, a handler demands a permission, and
// "any authenticated operator can kill any agent" is no longer true.
type Store interface {
	Verify(ctx context.Context, token string) (Operator, error)
}

// hashToken is how a presented token is compared against what Store
// loaded: SHA-256, hex-encoded, same shape internal/credentials uses
// for a credential secret, for the same reason, a token that leaked
// from this process's memory or a crash dump is still just a hash,
// not the thing itself.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
