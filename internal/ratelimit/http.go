package ratelimit

import (
	"net"
	"net/http"
	"strconv"

	niahttp "github.com/bogdanticu88/nia/internal/transport/http"
)

// ClientKey is the key the pre-authentication limiter uses: the
// caller's address, with the port stripped so one client opening many
// connections is still one key.
//
// trustForwarded decides whether X-Forwarded-For's leftmost entry wins.
// Off by default, and that default is the safe one: the header is
// attacker-controlled, so trusting it on a process reachable directly
// means anyone can get an unlimited number of fresh buckets by varying
// one header, which turns the limiter into decoration. Turn it on only
// when nothing can reach this process except a proxy that overwrites
// the header, see EnvTrustForwardedFor.
func ClientKey(r *http.Request, trustForwarded bool) string {
	if trustForwarded {
		if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
			// Leftmost entry is the original client in the convention
			// every proxy that appends to this header follows.
			for i := 0; i < len(fwd); i++ {
				if fwd[i] == ',' {
					return trimSpace(fwd[:i])
				}
			}
			return trimSpace(fwd)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func trimSpace(s string) string {
	start := 0
	for start < len(s) && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	end := len(s)
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}

// Middleware rejects a request with 429 when the caller's address has
// run out of tokens. A disabled limiter passes everything through
// untouched, so this is safe to install unconditionally.
//
// exempt names paths that are never limited. Both binaries pass their
// health endpoint: a load balancer's probe being throttled during
// exactly the traffic spike the limiter exists for would take the
// process out of rotation and make the overload worse. /metrics is
// deliberately not exempt, a scraper hitting it in a tight loop is
// itself load.
//
// onReject, when non-nil, is called with the key for each rejection, so
// a caller can count them without this package depending on
// internal/metrics.
func Middleware(l *Limiter, trustForwarded bool, onReject func(key string), next http.Handler, exempt ...string) http.Handler {
	if !l.Enabled() {
		return next
	}
	exemptSet := make(map[string]struct{}, len(exempt))
	for _, p := range exempt {
		exemptSet[p] = struct{}{}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := exemptSet[r.URL.Path]; ok {
			next.ServeHTTP(w, r)
			return
		}
		key := ClientKey(r, trustForwarded)
		if !l.Allow(key) {
			if onReject != nil {
				onReject(key)
			}
			// Retry-After in seconds, rounded up from how long one
			// token takes to refill, so a well-behaved client backs off
			// by roughly the right amount instead of guessing.
			wait := 1
			if l.rate > 0 {
				if s := int(1/l.rate) + 1; s > wait {
					wait = s
				}
			}
			w.Header().Set("Retry-After", strconv.Itoa(wait))
			niahttp.WriteError(w, http.StatusTooManyRequests, "rate limit exceeded, slow down")
			return
		}
		next.ServeHTTP(w, r)
	})
}
