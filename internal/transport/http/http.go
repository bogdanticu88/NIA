// Package http holds small transport helpers shared by cmd/api and
// cmd/gateway: consistent JSON responses and error handling so both
// entry points don't each reinvent it.
package http

import (
	"encoding/json"
	"log"
	"net/http"
)

// WriteJSON writes v as a JSON response with the given status code.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if v == nil {
		return
	}
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("http: encode response: %v", err)
	}
}

// WriteError writes a JSON error body: {"error": msg}.
func WriteError(w http.ResponseWriter, status int, msg string) {
	WriteJSON(w, status, map[string]string{"error": msg})
}

// DefaultMaxRequestBytes is the inbound body cap both binaries apply.
// One MiB is far above anything this control plane legitimately
// receives, the largest real body is a grants list or a tool-call
// arguments object, and far below what would matter if someone streamed
// at a process with no limit at all.
//
// Before this, every handler in both binaries called
// json.NewDecoder(r.Body).Decode directly with nothing bounding it, so
// an unauthenticated POST with an endless body was read until the
// process ran out of memory. Fourteen decode sites, which is exactly
// why this is middleware over the whole mux rather than a change at
// each one: a fifteenth handler written next year inherits the cap
// without anyone remembering it exists.
const DefaultMaxRequestBytes int64 = 1 << 20

// MaxBytes wraps h so every request body is capped at n bytes. Reading
// past the cap makes the body return an error, which each handler
// already turns into a 400 through its existing decode-error path, so
// this needs no handler changes to be effective.
//
// http.MaxBytesReader also sets the response status to 413 itself when
// the handler has not written one yet, so an oversized body gets the
// right code rather than a generic parse failure.
func MaxBytes(h http.Handler, n int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, n)
		}
		h.ServeHTTP(w, r)
	})
}
