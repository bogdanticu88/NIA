package main

import (
	"context"
	"net/http"
	"strings"

	"github.com/bogdanticu88/nia/internal/opauth"
	niahttp "github.com/bogdanticu88/nia/internal/transport/http"
)

type operatorContextKey struct{}

// operatorFromContext returns the authenticated operator's name and
// whether one was actually established. A handler uses this in
// preference to a client-supplied operator/*_by field whenever it's
// present, see e.g. handleKill: when opauth is configured, the caller
// cannot claim to be anyone but who their token says they are; when
// it's not configured (ok is always false in that case, the
// middleware in routes() never runs), a handler falls back to the
// client-supplied field, same behavior as before this package existed.
func operatorFromContext(ctx context.Context) (string, bool) {
	name, ok := ctx.Value(operatorContextKey{}).(string)
	return name, ok
}

// resolveOperator is the one-line idiom every handler that attributes
// an action to an operator uses: prefer the authenticated identity,
// fall back to whatever the request body claimed. claimed is kept even
// when authenticated so an operator acting on behalf of an automated
// system (niactl simulate, a script) can still leave a human-readable
// note in the same field, cmd/api doesn't have a separate "on behalf
// of" concept, this is deliberately simple rather than modeling one.
func resolveOperator(ctx context.Context, claimed string) string {
	if name, ok := operatorFromContext(ctx); ok {
		return name
	}
	return claimed
}

// operatorAuthMiddleware requires "Authorization: Bearer <token>" on
// every request and rejects anything else with 401, verified against
// store. This only ever wraps the mux when NIA_OPERATOR_TOKENS_PATH is
// set (see routes() and opauth.FromEnv's own doc comment on why unset
// means store is nil and this function is never called at all): the
// default, unconfigured posture is unchanged from before this package
// existed, cmd/api trusts whatever the request body says, a real,
// named, and still-open gap, see docs/THREAT_MODEL.md's threats 1 and
// 2's "Not covered" sections and docs/SECURITY_INVARIANTS.md invariant
// 11's own "Status" line for the honest statement of what this does
// and doesn't close.
//
// GET /healthz and GET /metrics are deliberately exempt: a
// load-balancer health check or a Prometheus scraper hitting this
// process shouldn't need an operator token, neither endpoint reveals
// anything about a specific agent, credential, or grant.
func operatorAuthMiddleware(store opauth.Store, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" || r.URL.Path == "/metrics" {
			next.ServeHTTP(w, r)
			return
		}
		raw := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if !strings.HasPrefix(raw, prefix) {
			niahttp.WriteError(w, http.StatusUnauthorized, "missing or malformed Authorization header, expected: Bearer <operator token>")
			return
		}
		token := strings.TrimPrefix(raw, prefix)
		op, err := store.Verify(r.Context(), token)
		if err != nil {
			if err == opauth.ErrInvalidToken {
				niahttp.WriteError(w, http.StatusUnauthorized, "invalid operator token")
				return
			}
			// Same fail-closed reasoning cmd/gateway/authn.go's
			// credentialResolver applies: a Store that couldn't
			// answer (StaticStore never hits this today, it's pure
			// in-memory; a future database-backed Store could) is not
			// the same outcome as an invalid token, and must not be
			// treated as either an allow or the same 401 an actually
			// wrong token gets.
			niahttp.WriteError(w, http.StatusInternalServerError, "could not verify operator token")
			return
		}
		ctx := context.WithValue(r.Context(), operatorContextKey{}, op.Name)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
