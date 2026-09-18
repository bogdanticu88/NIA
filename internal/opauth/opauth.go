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
// deliberately doesn't have: rotation or expiry (a leaked token has to
// be removed from the source file and the process restarted, there's no
// live revoke the way internal/credentials has). That is a real, open
// gap, named here rather than implied solved.
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
