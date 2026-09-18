package opauth

import (
	"context"
	"time"
)

// StaticStore is the reference (and, for now, only) Store
// implementation: a fixed map of token digest to Operator built once
// at startup from whatever FromEnv loaded. No mutation methods exist
// on purpose, rotating or revoking a token today means editing the
// source file and restarting the process, see this package's own doc
// comment for why that's a stated, accepted gap rather than something
// this type pretends to handle.
type StaticStore struct {
	byDigest map[string]Operator
}

// NewStaticStore builds a StaticStore from token to operator-name
// pairs, giving every operator RoleAdmin. Kept for tests and for
// callers that genuinely want one all-powerful token; FromEnv uses
// NewStaticStoreWithOperators so a real deployment declares roles
// explicitly. Plaintext tokens are hashed immediately and never
// retained, same posture as internal/credentials.Issue never keeping
// the plaintext secret around after handing it back once.
func NewStaticStore(tokens map[string]string) *StaticStore {
	ops := make(map[string]Operator, len(tokens))
	for token, name := range tokens {
		ops[token] = Operator{Name: name, Roles: []Role{RoleAdmin}}
	}
	return NewStaticStoreWithOperators(ops)
}

// NewStaticStoreWithOperators builds a StaticStore from token to
// Operator, roles included.
func NewStaticStoreWithOperators(operators map[string]Operator) *StaticStore {
	s := &StaticStore{byDigest: make(map[string]Operator, len(operators))}
	for token, op := range operators {
		s.byDigest[hashToken(token)] = op
	}
	return s
}

func (s *StaticStore) Verify(_ context.Context, token string) (Operator, error) {
	if token == "" {
		return Operator{}, ErrInvalidToken
	}
	// A plain map lookup on the SHA-256 digest is enough here: the
	// lookup key is already a fixed-size hash rather than the raw
	// secret, so this isn't the single-candidate secret comparison
	// internal/credentials.Verify has to make constant-time (it looks
	// a credential up by id first, then compares one presented secret
	// against that one stored digest). A map lookup across many
	// digests doesn't have that shape or that risk.
	op, ok := s.byDigest[hashToken(token)]
	if !ok {
		return Operator{}, ErrInvalidToken
	}
	if op.Expired(time.Now()) {
		// Collapsed into the same error as an unknown token, same
		// reasoning ErrInvalidToken's own doc comment gives: a caller
		// probing which specific reason a token failed gets no signal
		// to work with.
		return Operator{}, ErrInvalidToken
	}
	return op, nil
}
