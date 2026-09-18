package opauth

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// envTokensPath names a JSON file of operator tokens. Unset means
// operator authentication is not configured at all, cmd/api runs the
// way it always has, trusting whatever operator/*_by field a request
// body supplies, see cmd/api/opauth.go's middleware for exactly what
// changes when this is set. This is a stronger "off" than
// internal/sensitivity's or internal/registry/tools's FromEnv
// constructors: those return a real, usable value in the empty state
// (every resource Public, an empty catalog); this one returns a nil
// Store, because there is no safe non-nil default for "verify a
// caller's identity", an empty StaticStore would just reject every
// token, indistinguishable from a misconfigured deployment locking
// itself out.
const envTokensPath = "NIA_OPERATOR_TOKENS_PATH"

// EnvAllowUnauthenticated is the explicit, loudly-named opt out of
// operator authentication, the same shape cmd/gateway's
// NIA_GATEWAY_INSECURE_HEADER_AUTH already had for its own
// authentication. One variable covers both binaries on purpose: a
// deployment that decides to run open should say so once, in a way
// that's visible in the same place for nia-api and nia-gateway, not
// per-process.
//
// It exists because local development genuinely needs a way to run
// without minting tokens first, and because a hard requirement with no
// escape hatch gets worked around in worse ways. What it must never be
// is the default, see FromEnvEnforced.
const EnvAllowUnauthenticated = "NIA_ALLOW_UNAUTHENTICATED"

// tokenFile is one entry in the JSON file NIA_OPERATOR_TOKENS_PATH
// points at: a flat array of
// {"token": "...", "name": "...", "roles": ["operator"]}.
//
// roles is required and must name at least one known role, see
// roles.go. Not optional-with-a-default on purpose: defaulting to admin
// would silently keep the gap roles exist to close, and defaulting to
// viewer would silently break a deployment that thought it had granted
// more. An explicit list is the only reading that cannot be wrong by
// accident, and the startup error names the valid roles.
//
// The
// plaintext token lives in this file because something has to, the
// same tradeoff NIA_TESSERA_JWT_SIGNING_KEY and TESSERA_JWT_SIGNING_KEY
// already make for a different shared secret, an operator managing
// this file is expected to treat it like any other credential store
// and keep it out of version control.
type tokenFile struct {
	Token string   `json:"token"`
	Name  string   `json:"name"`
	Roles []string `json:"roles"`
	// ExpiresAt is optional, RFC3339. A token past it stops
	// authenticating without anyone having to remember to remove it,
	// which is the point: the tokens that actually leak are the ones
	// issued for a migration eighteen months ago that nobody revisited.
	ExpiresAt string `json:"expires_at,omitempty"`
}

// FromEnv builds a Store from the tokens file named by
// NIA_OPERATOR_TOKENS_PATH. Unset returns (nil, nil), not an error,
// and not a usable Store either, see envTokensPath's own doc comment;
// cmd/api's caller must treat a nil Store as "operator auth is off",
// the same way it already treats a nil sensitivity.Classifier as
// impossible (that package's FromEnv never returns nil) versus a nil
// credentials.Store as impossible too, this package is the one place
// in this codebase where nil, no error is the expected default rather
// than something a caller has to guard defensively against.
func FromEnv() (Store, error) {
	path := os.Getenv(envTokensPath)
	if path == "" {
		return nil, nil
	}
	// ReloadingStore rather than a bare StaticStore: removing a line
	// from the token file takes effect on every process reading it
	// within a couple of seconds, which is the closest thing this
	// package has to revocation, see reloading.go.
	return NewReloadingStore(path)
}

// loadTokenFile parses the token file at path and returns a store plus
// the modification time and size it was read at, which ReloadingStore
// uses to notice a later change without re-parsing on every request.
func loadTokenFile(path string) (*StaticStore, time.Time, int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, time.Time{}, 0, fmt.Errorf("opauth: reading %s (%s): %w", envTokensPath, path, err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, time.Time{}, 0, fmt.Errorf("opauth: reading %s (%s): %w", envTokensPath, path, err)
	}
	var files []tokenFile
	if err := json.Unmarshal(raw, &files); err != nil {
		return nil, time.Time{}, 0, fmt.Errorf("opauth: parsing %s: %w", path, err)
	}
	if len(files) == 0 {
		return nil, time.Time{}, 0, fmt.Errorf("opauth: %s is set but %s contains no tokens, a deployment would lock every operator out, remove the env var instead if that's genuinely intended", envTokensPath, path)
	}

	operators := make(map[string]Operator, len(files))
	for i, f := range files {
		if f.Token == "" {
			return nil, time.Time{}, 0, fmt.Errorf("opauth: entry %d in %s has an empty token", i, path)
		}
		if f.Name == "" {
			return nil, time.Time{}, 0, fmt.Errorf("opauth: entry %d in %s (token present) has an empty name", i, path)
		}
		if len(f.Roles) == 0 {
			return nil, time.Time{}, 0, fmt.Errorf("opauth: entry %d (%s) in %s declares no roles, add at least one of: %s", i, f.Name, path, strings.Join(KnownRoles(), ", "))
		}
		roles := make([]Role, 0, len(f.Roles))
		for _, rawRole := range f.Roles {
			role, err := ParseRole(rawRole)
			if err != nil {
				return nil, time.Time{}, 0, fmt.Errorf("opauth: entry %d (%s) in %s: %w", i, f.Name, path, err)
			}
			roles = append(roles, role)
		}

		op := Operator{Name: f.Name, Roles: roles}
		if f.ExpiresAt != "" {
			exp, err := time.Parse(time.RFC3339, f.ExpiresAt)
			if err != nil {
				return nil, time.Time{}, 0, fmt.Errorf("opauth: entry %d (%s) in %s has an expires_at that is not RFC3339 (want e.g. 2026-12-31T23:59:59Z): %w", i, f.Name, path, err)
			}
			op.ExpiresAt = &exp
		}
		operators[f.Token] = op
	}
	return NewStaticStoreWithOperators(operators), info.ModTime(), info.Size(), nil
}

// FromEnvEnforced is FromEnv with the deployment posture inverted:
// unset NIA_OPERATOR_TOKENS_PATH is an error, not a silently open
// process, unless NIA_ALLOW_UNAUTHENTICATED=1 says otherwise
// explicitly.
//
// This is the whole point of the change: FromEnv's own default (nil
// Store, no error) meant a deployment that never set the variable ran
// its control plane wide open, and the only thing standing between
// that and a real incident was someone remembering to set an env var
// nobody's compose file set either. cmd/gateway already had this
// right, its insecure path needs NIA_GATEWAY_INSECURE_HEADER_AUTH=1,
// cmd/api had it backwards. Both binaries call this now.
//
// The returned Store is nil only in the allow-unauthenticated case,
// and the second return value says which of the two situations
// produced a nil Store so a caller can log the difference rather than
// guessing.
func FromEnvEnforced() (store Store, allowedUnauthenticated bool, err error) {
	store, err = FromEnv()
	if err != nil {
		return nil, false, err
	}
	if store != nil {
		return store, false, nil
	}
	if os.Getenv(EnvAllowUnauthenticated) == "1" {
		return nil, true, nil
	}
	return nil, false, fmt.Errorf(
		"opauth: %s is not set, so this process would accept every request unauthenticated: point it at a tokens file, or set %s=1 to run open on purpose (never do that on anything reachable by an untrusted caller)",
		envTokensPath, EnvAllowUnauthenticated,
	)
}
