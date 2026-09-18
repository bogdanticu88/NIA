package opauth

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	niahttp "github.com/bogdanticu88/nia/internal/transport/http"
)

// contextKey is the private key type operator identity is stashed
// under. Unexported and a distinct type so nothing outside this
// package can collide with it or forge an entry by writing a plain
// string key into a context.
type contextKey struct{}

// FromContext returns the authenticated operator, roles included, and
// whether one was actually established. A handler uses this in
// preference to any operator/*_by field a request body supplies: when
// Middleware ran, the caller cannot claim to be anyone but who their
// token says they are.
func FromContext(ctx context.Context) (Operator, bool) {
	op, ok := ctx.Value(contextKey{}).(Operator)
	return op, ok
}

// OperatorFromContext returns just the authenticated operator's name,
// the shape every audit-writing handler wants.
func OperatorFromContext(ctx context.Context) (string, bool) {
	op, ok := FromContext(ctx)
	return op.Name, ok
}

// withOperator is the only way an Operator gets into the context under
// contextKey, kept unexported so the only path to an "authenticated"
// operator identity is through Middleware actually verifying a token.
func withOperator(ctx context.Context, op Operator) context.Context {
	return context.WithValue(ctx, contextKey{}, op)
}

// Require wraps a handler so it only runs for an operator holding perm.
// An authenticated caller without it gets 403, which is a different
// answer from the 401 an unauthenticated one gets and deliberately so:
// "I don't know who you are" and "I know exactly who you are and you
// may not do this" are different facts, and an operator debugging their
// own access needs to be able to tell them apart.
//
// A request that never went through Middleware has no operator in its
// context at all. That happens only when the process is running with
// NIA_ALLOW_UNAUTHENTICATED=1, where there is no identity to authorize
// and every request is already trusted, so this passes through rather
// than refusing: refusing would make the escape hatch useless without
// making anything safer.
func Require(perm Permission, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		op, ok := FromContext(r.Context())
		if !ok {
			next.ServeHTTP(w, r)
			return
		}
		if !op.Can(perm) {
			niahttp.WriteError(w, http.StatusForbidden, fmt.Sprintf("operator %q holds roles %s, which do not include the %q permission this endpoint requires", op.Name, strings.Join(op.RoleNames(), ", "), perm))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// bearerPrefix is the scheme an operator token must be presented with.
const bearerPrefix = "Bearer "

// Middleware requires "Authorization: Bearer <token>" and rejects
// anything else with 401, verified against store. On success the
// authenticated operator's name is put in the request context, readable
// with OperatorFromContext.
//
// exempt names paths that skip the check entirely. Both binaries pass
// their health and metrics endpoints: a load-balancer probe or a
// Prometheus scrape shouldn't need an operator token, and neither
// endpoint reveals anything about a specific agent, credential, or
// grant. Matching is exact, not prefix-based, so an exemption can never
// accidentally cover a subtree (exempting "/metrics" must not also
// exempt "/metrics/agents/secret").
//
// store must not be nil. A caller that has no store has no way to
// authenticate anyone and must not be calling this at all, see
// FromEnvEnforced for how both binaries decide that up front rather
// than degrading to an open surface at request time.
func Middleware(store Store, next http.Handler, exempt ...string) http.Handler {
	exemptSet := make(map[string]struct{}, len(exempt))
	for _, p := range exempt {
		exemptSet[p] = struct{}{}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := exemptSet[r.URL.Path]; ok {
			next.ServeHTTP(w, r)
			return
		}
		raw := r.Header.Get("Authorization")
		if !strings.HasPrefix(raw, bearerPrefix) {
			niahttp.WriteError(w, http.StatusUnauthorized, "missing or malformed Authorization header, expected: Bearer <operator token>")
			return
		}
		op, err := store.Verify(r.Context(), strings.TrimPrefix(raw, bearerPrefix))
		if err != nil {
			if err == ErrInvalidToken {
				niahttp.WriteError(w, http.StatusUnauthorized, "invalid operator token")
				return
			}
			// Same fail-closed reasoning cmd/gateway/authn.go's
			// credentialResolver applies: a Store that couldn't answer
			// (StaticStore never hits this today, it's pure in-memory;
			// a future database-backed Store could) is not the same
			// outcome as an invalid token, and must not be treated as
			// either an allow or the same 401 an actually wrong token
			// gets.
			niahttp.WriteError(w, http.StatusInternalServerError, "could not verify operator token")
			return
		}
		next.ServeHTTP(w, r.WithContext(withOperator(r.Context(), op)))
	})
}
