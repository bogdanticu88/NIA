package opauth

import "context"

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
// pairs. Plaintext tokens are hashed immediately and never retained,
// same posture as internal/credentials.Issue never keeping the
// plaintext secret around after handing it back once.
func NewStaticStore(tokens map[string]string) *StaticStore {
	s := &StaticStore{byDigest: make(map[string]Operator, len(tokens))}
	for token, name := range tokens {
		s.byDigest[hashToken(token)] = Operator{Name: name}
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
	return op, nil
}
