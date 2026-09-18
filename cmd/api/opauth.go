package main

import (
	"context"
	"net/http"

	"github.com/bogdanticu88/nia/internal/opauth"
)

// operatorFromContext returns the authenticated operator's name and
// whether one was actually established. Thin pass-through to
// opauth.OperatorFromContext: the context key moved into that package
// when cmd/gateway needed the same middleware, this stays so every
// call site in this file reads the same way it did before.
func operatorFromContext(ctx context.Context) (string, bool) {
	return opauth.OperatorFromContext(ctx)
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
// store.
//
// GET /healthz and GET /metrics are deliberately exempt: a
// load-balancer health check or a Prometheus scraper hitting this
// process shouldn't need an operator token, neither endpoint reveals
// anything about a specific agent, credential, or grant.
//
// The implementation lives in internal/opauth now, cmd/gateway wraps
// its own operator-facing read endpoints with the same thing. This
// wrapper stays because routes() and this package's tests both read
// better naming the two exempt paths in one place than repeating them
// at the call site.
func operatorAuthMiddleware(store opauth.Store, next http.Handler) http.Handler {
	return opauth.Middleware(store, next, "/healthz", "/metrics")
}
