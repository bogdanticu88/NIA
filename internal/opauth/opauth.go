// Package opauth authenticates the human or system callers of
// cmd/api's own HTTP surface, the control plane an operator drives
// through niactl or a script.
//
// This is a different problem from internal/credentials: that package
// authenticates an agent (an NHI) to cmd/gateway's hot path, this one
// authenticates whoever is allowed to register agents, write grants,
// pull the kill switch, and read the audit trail in the first place.
// Before this package existed, cmd/api trusted whatever "operator"
// string a caller put in a request body, register an agent as
// "owner":"bogdan" and kill it as "operator":"bogdan" and the API
// believed both, no proof required, see the security hardening
// directive's own audit findings. That's a real, named gap, and this
// package closes the authentication half of it (a verified caller
// identity), not the authorization half (what that identity is
// allowed to do): every operator this package can authenticate can
// still do everything cmd/api exposes, there's no per-operator scoping
// yet, see this package's own doc comment on Store for the honest
// statement of that boundary.
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
// deliberately doesn't have: per-operator scoping (every valid token
// can do everything cmd/api exposes), rotation or expiry (a leaked
// token has to be removed from the source file and the process
// restarted, there's no live revoke the way internal/credentials has),
// and any notion of roles. All three are real, open gaps, named here
// rather than implied solved, closing them is separate work if cmd/api
// ever has enough distinct operators or enough at stake to need it.
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
