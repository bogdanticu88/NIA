// Package credentials owns the credential lifecycle for a non-human
// identity: issuance, rotation, revocation, and, as of the security
// hardening pass, verification. This is explicitly something Tessera
// does not do; Tessera's IIdentityResolver assumes a credential already
// exists and only resolves it to a canonical AgentRef. NIA mints,
// verifies, and retires the credentials that resolution depends on.
//
// Before this pass, Issue returned a bare random ID and nothing else,
// no secret material at all, see docs/THREAT_MODEL.md's original threat
// 1/2 writeup. That ID was also returned by GET /agents/{ref}/credentials,
// an unauthenticated endpoint, so it could never have doubled as a
// bearer secret even if something had tried to use it as one: it was a
// public identifier, not a proof of possession. This package now
// generates real secret material at Issue and Rotate time, returns the
// plaintext exactly once to the caller, and stores only a SHA-256 digest
// of it. Nothing in this package or its callers can recover a
// previously-issued secret from what's stored, only verify a presented
// one against the digest.
//
// The bearer credential a caller presents is "<id>.<secret>": the ID is
// how Verify finds the right row without a table scan, the secret is
// what actually proves possession. Neither half is meaningful alone,
// knowing an ID (which, same as before, GET /agents/{ref}/credentials
// still returns) does not let anyone authenticate as that credential.
//
// Revocation here is a smaller action than the kill switch in
// internal/policy: revoking a credential retires one key without
// touching the agent's grants or identity. Killing an agent (see
// internal/policy.Client.Kill) is the bigger hammer, use it when the
// agent itself is compromised, not just one leaked key. As of this
// pass, a kill also cascades into revoking every active credential the
// killed agent holds, see internal/monitoring.Monitor.Observe and
// cmd/api's handleKill, closing the gap where a killed agent's old
// credentials sat around reporting "active" forever.
package credentials

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

// Kind is the credential type. NIA doesn't generate cryptographic
// material for mTLS certificates in this scaffold; a KindMTLSCert
// credential still gets a bearer secret from this package the same way
// api_key and oauth_token do, so Verify has one uniform code path, but
// a real deployment authenticating mTLS clients should verify the TLS
// handshake's certificate thumbprint instead of a bearer secret. That
// swap is not implemented here, documented as a known simplification
// rather than pretended away.
type Kind string

const (
	KindAPIKey     Kind = "api_key"
	KindOAuthToken Kind = "oauth_token"
	KindMTLSCert   Kind = "mtls_cert"
)

// Status is where a credential sits in its own lifecycle. Four states,
// matching the security hardening directive's own list: Active is
// usable, the other three are not, and are terminal from Verify's point
// of view for different reasons. Revoked is a one-way security action
// (an operator, an incident, a cascading kill). Expired is time-based
// and computed, not just stored, see Credential.Effective: nothing
// needs to run a background sweep for an expired credential to stop
// authenticating, the check happens at Verify time regardless of what
// the stored Status column says. Disabled is the one reversible
// administrative state, a temporary pause distinct from a security
// revoke, see Store.Disable and Store.Enable.
type Status string

const (
	StatusActive   Status = "active"
	StatusRevoked  Status = "revoked"
	StatusExpired  Status = "expired"
	StatusDisabled Status = "disabled"
)

// Credential is metadata about one issued credential. The plaintext
// secret never lives here, only its SHA-256 digest (SecretHash, hex
// encoded), same reasoning a password table stores a hash, not the
// password. The secret has 256 bits of entropy from crypto/rand, a fast
// hash is standard practice here the way it is for API tokens (GitHub,
// Stripe, and others all do the same thing), there is no offline
// guessing risk a slow password hash (bcrypt/scrypt/argon2) would
// defend against, the entropy is already in the secret, not derived
// from anything guessable.
type Credential struct {
	ID       string
	AgentRef string
	Kind     Kind
	Status   Status
	// SecretHash is tagged json:"-": every handler in cmd/api that
	// returns a Credential (handleIssueCredential, handleListCredentials,
	// handleRevokeCredential, and the rest) serializes this struct
	// straight to JSON, and before this field carried a tag it went out
	// on every one of those responses. A hex SHA-256 digest isn't
	// reversible to the secret it was computed from, so this was never
	// the same class of exposure as leaking the secret itself would be,
	// but it's still exactly the surface the security hardening
	// directive names directly: "credential hashes/digests must not be
	// exposed through APIs or logs." Verified live against a real
	// running nia-api: before this tag, `niactl credential issue`'s own
	// JSON response body carried a SecretHash field in plain sight.
	// Nothing inside this package reads SecretHash through JSON, Verify
	// and every Store implementation compare against the in-memory or
	// database-column value directly, so this costs nothing internally.
	SecretHash  string `json:"-"`
	IssuedAt    time.Time
	ExpiresAt   *time.Time
	RevokedAt   *time.Time
	RevokedBy   string
	Reason      string
	DisabledAt  *time.Time
	DisabledBy  string
	EnabledAt   *time.Time
	RotatedFrom string // set on the new credential Rotate creates, the ID it replaced
	RotatedTo   string // set on the old credential once Rotate has replaced it

	// Thumbprint is the hex SHA-256 of the DER bytes of the client
	// certificate this credential is bound to, set only for KindMTLSCert
	// credentials created through BindCertificate.
	//
	// A certificate binding is deliberately a credential rather than a
	// separate concept. It is the same thing every other credential is,
	// a named, revocable, expirable proof that a particular NHI is the
	// caller, and modelling it here means revocation, expiry, disable,
	// the kill cascade and the audit trail all apply to it without a
	// second implementation of each. The difference is only what counts
	// as proof: a secret the caller knows, or a private key the caller
	// demonstrably holds during the TLS handshake.
	//
	// Tagged json:"-" for the same reason SecretHash is. It is not
	// secret, a thumbprint is public information, but it is also not
	// something any API response has a reason to carry, and the fewer
	// identifiers that leak into logs and response bodies the better.
	Thumbprint string `json:"-"`
}

// Effective returns the status that actually governs whether this
// credential can authenticate right now, evaluated against now rather
// than trusted from the stored Status column. Revoked and Disabled are
// stored decisions and take precedence over everything else, they are
// facts about what an operator or the system already decided, not
// conditions that can un-happen by the clock moving. Absent either of
// those, an ExpiresAt in the past means Expired regardless of what
// Status says, closing the gap where nothing used to compute this at
// all, see this package's own doc comment.
func (c Credential) Effective(now time.Time) Status {
	if c.Status == StatusRevoked {
		return StatusRevoked
	}
	if c.Status == StatusDisabled {
		return StatusDisabled
	}
	if c.ExpiresAt != nil && !now.Before(*c.ExpiresAt) {
		return StatusExpired
	}
	return StatusActive
}

var (
	ErrNotFound = errors.New("credentials: not found")
	// ErrInvalidCredential is returned by Verify for every failure mode,
	// not found, wrong secret, or a credential whose Effective status
	// isn't Active. Deliberately one error for all of them: an attacker
	// probing which failure they hit (a real id with a wrong secret
	// versus an id that doesn't exist at all versus a revoked one) is
	// exactly the information a real deployment shouldn't leak.
	ErrInvalidCredential = errors.New("credentials: invalid credential")
)

// Store is where credential metadata and secret digests live. A
// production deployment backs this with Postgres (see postgres.go,
// FromEnv); InMemoryStore is the reference implementation used for
// local dev and most tests, same pattern as internal/audit and
// internal/policy.
type Store interface {
	// Issue mints a new credential for agentRef and returns the
	// plaintext secret exactly once, alongside the metadata record. The
	// caller is responsible for getting that secret to the agent
	// through some out-of-band channel, this package never stores it or
	// hands it back again.
	Issue(ctx context.Context, agentRef string, kind Kind, ttl time.Duration) (Credential, string, error)

	Get(ctx context.Context, id string) (Credential, error)
	ListForAgent(ctx context.Context, agentRef string) ([]Credential, error)

	// Revoke retires a credential permanently. A security action:
	// an operator decision, an incident, or a cascading agent kill.
	Revoke(ctx context.Context, id, revokedBy, reason string) error

	// Disable is the reversible counterpart to Revoke, an
	// administrative pause (an agent taken offline for maintenance,
	// say) rather than a security decision. A disabled credential
	// cannot authenticate, same as a revoked one, but can be brought
	// back with Enable, a revoked one never can.
	Disable(ctx context.Context, id, disabledBy, reason string) error
	Enable(ctx context.Context, id, enabledBy string) error

	// Rotate atomically revokes id (Reason records the rotation,
	// RotatedTo is set to the new credential's ID) and issues a
	// replacement for the same agent and kind, returning the new
	// credential and its plaintext secret. "Atomically" here means what
	// it means everywhere else in this codebase, see
	// docs/SECURITY_INVARIANTS.md: within one Store implementation this
	// is a single critical section, there is no window where both the
	// old and new credential are simultaneously valid, and no window
	// where neither is, an implementation must not issue the new
	// credential and then separately revoke the old one as two
	// observable steps.
	Rotate(ctx context.Context, id, rotatedBy string, ttl time.Duration) (Credential, string, error)

	// Verify checks a presented secret against id's stored digest and
	// returns the credential only if it matches AND Effective(now) ==
	// StatusActive. Every other outcome, wrong secret, unknown id,
	// revoked, expired, disabled, returns ErrInvalidCredential and
	// nothing else, see that error's own doc comment for why the
	// failure modes are deliberately indistinguishable from outside
	// this package.
	Verify(ctx context.Context, id, presentedSecret string) (Credential, error)

	// BindCertificate binds a client certificate, identified by the hex
	// SHA-256 of its DER bytes, to agentRef. The result is a
	// KindMTLSCert credential with no secret: the proof of possession is
	// the TLS handshake, not something the caller sends.
	//
	// Binding is explicit and required. A certificate signed by a
	// trusted CA is a certificate the deployment trusts the issuer of,
	// which is a different statement from "this certificate is agent X",
	// and treating the first as the second would make every certificate
	// any trusted CA ever issues into an authenticated agent. This is
	// the step that turns a validated certificate into an identity.
	BindCertificate(ctx context.Context, agentRef, thumbprint string) (Credential, error)

	// VerifyCertificate resolves a thumbprint to the credential bound to
	// it, and only if that credential's Effective status is Active. An
	// unbound, revoked, expired or disabled binding returns
	// ErrInvalidCredential, the same undifferentiated error Verify
	// returns, for the same reason.
	VerifyCertificate(ctx context.Context, thumbprint string) (Credential, error)
}

// ThumbprintOf is the one definition of a certificate's thumbprint in
// this codebase: hex-encoded SHA-256 over the certificate's DER bytes,
// which is what RFC 8705 calls the certificate thumbprint and what every
// other tool that prints one produces.
//
// It takes raw DER rather than an x509.Certificate so there is no way to
// accidentally hash a parsed, re-encoded, or partially populated
// certificate and get a value that does not match what the peer actually
// presented.
func ThumbprintOf(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// newSecret generates a fresh high-entropy bearer secret and its hex
// SHA-256 digest. 32 bytes of crypto/rand entropy, base64url encoded
// (no padding, so it's safe inside a bearer token without extra
// escaping) for the plaintext half; the digest is what actually gets
// stored.
func newSecret() (plaintext, digestHex string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	plaintext = base64.RawURLEncoding.EncodeToString(b)
	return plaintext, hashSecret(plaintext), nil
}

func hashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// secretsMatch compares a presented secret's digest against a stored
// digest in constant time. Both are fixed-length hex strings already,
// so this avoids the timing side channel a plain == comparison would
// have on the digest bytes, and it avoids hashing an unbounded
// attacker-controlled input against a variable-time comparison of raw
// secrets, comparing the digests is both simpler and no weaker, since
// the digest is a deterministic function of the secret.
func secretsMatch(presentedDigest, storedDigest string) bool {
	return subtle.ConstantTimeCompare([]byte(presentedDigest), []byte(storedDigest)) == 1
}

// absentDigest is what a presented secret gets compared against when
// the id it named doesn't exist. It's a real, fixed, 64-character hex
// string so the comparison has the same shape and length as a genuine
// one, and it is not the digest of any secret this package can ever
// issue: newSecret's plaintext is 43 base64url characters of 256-bit
// entropy, and sha256 of anything is what this is deliberately not.
var absentDigest = strings.Repeat("ff", sha256.Size)

// verifyPresented is the shared tail of both Store implementations'
// Verify. It exists so neither of them returns early on "no such id":
// an early return skips the hash and the comparison entirely, which
// makes an unknown id measurably faster to reject than a real id with
// a wrong secret, and that difference is an oracle telling an attacker
// which credential ids exist. ErrInvalidCredential's own doc comment
// says those failures are deliberately indistinguishable to the
// caller, this is what makes that true in timing as well as in the
// returned error.
//
// The work is the same either way: hash the presented secret, compare
// it in constant time against either the stored digest or absentDigest,
// then check the effective status. A caller still learns nothing from
// the outcome, every path returns the same error.
func verifyPresented(c Credential, found bool, presentedSecret string, now time.Time) (Credential, error) {
	stored := absentDigest
	if found {
		stored = c.SecretHash
	}
	match := secretsMatch(hashSecret(presentedSecret), stored)
	if !found || !match {
		return Credential{}, ErrInvalidCredential
	}
	if c.Effective(now) != StatusActive {
		return Credential{}, ErrInvalidCredential
	}
	return c, nil
}

func randomID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
