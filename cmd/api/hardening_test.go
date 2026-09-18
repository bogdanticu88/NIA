package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bogdanticu88/nia/internal/opauth"
	"github.com/bogdanticu88/nia/internal/ratelimit"
	niahttp "github.com/bogdanticu88/nia/internal/transport/http"
)

// TestRoutes_OversizedBodyIsRefused covers the cap that replaced
// fourteen unbounded json.NewDecoder(r.Body) calls. Before it, an
// unauthenticated POST with an endless body was read until the process
// ran out of memory.
func TestRoutes_OversizedBodyIsRefused(t *testing.T) {
	s := newTestServer()
	body := strings.NewReader(`{"ref":"agent:x","purpose":"` + strings.Repeat("A", int(niahttp.DefaultMaxRequestBytes)+1024) + `"}`)

	req := httptest.NewRequest(http.MethodPost, "/agents", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)

	// The handler's own decode-error path turns the capped read into a
	// 400, and MaxBytesReader sets 413 when nothing has been written
	// yet. Either is a refusal, which is the property that matters, the
	// body was not read to completion.
	if rec.Code != http.StatusRequestEntityTooLarge && rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 413 or 400 for a body over the cap", rec.Code)
	}
}

func TestRoutes_BodyUnderTheCapStillWorks(t *testing.T) {
	s := newTestServer()
	req := httptest.NewRequest(http.MethodPost, "/agents", strings.NewReader(`{"ref":"agent:under-cap","owner":"bogdan"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated && rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want the registration to succeed: %s", rec.Code, rec.Body.String())
	}
}

func TestRoutes_RateLimitRefusesAFloodFromOneClient(t *testing.T) {
	s := newTestServer()
	// One request per second, burst of 3, so the fourth in a tight loop
	// is refused.
	s.limiter = ratelimit.New(1, 3)

	call := func() int {
		req := httptest.NewRequest(http.MethodGet, "/agents", nil)
		req.RemoteAddr = "203.0.113.7:4444"
		rec := httptest.NewRecorder()
		s.routes().ServeHTTP(rec, req)
		return rec.Code
	}

	for i := 0; i < 3; i++ {
		if got := call(); got == http.StatusTooManyRequests {
			t.Fatalf("request %d inside the burst was refused", i+1)
		}
	}
	if got := call(); got != http.StatusTooManyRequests {
		t.Fatalf("status = %d past the burst, want 429", got)
	}
}

// TestRoutes_RateLimitAppliesBeforeAuthentication is the ordering that
// makes this worth having: an attacker who never presents a valid token
// still costs this process a token-store lookup per request, and none of
// those requests is audited, there is no operator to attribute them to.
func TestRoutes_RateLimitAppliesBeforeAuthentication(t *testing.T) {
	s := newTestServerWithOpauth(opauth.NewStaticStore(map[string]string{"tok": "bogdan"}))
	s.limiter = ratelimit.New(1, 1)

	call := func() int {
		req := httptest.NewRequest(http.MethodGet, "/agents", nil)
		req.RemoteAddr = "203.0.113.9:5555"
		rec := httptest.NewRecorder()
		s.routes().ServeHTTP(rec, req)
		return rec.Code
	}

	// The first request passes the limiter and is then rejected by
	// authentication for having no Authorization header.
	if got := call(); got != http.StatusUnauthorized {
		t.Fatalf("first request status = %d, want 401", got)
	}
	// The second never reaches authentication. If the limiter sat
	// behind the auth middleware instead, this would be another 401 and
	// the flood would still be costing a token lookup per request.
	if got := call(); got != http.StatusTooManyRequests {
		t.Fatalf("second request status = %d, want 429 from the limiter in front of authentication", got)
	}
}

func TestRoutes_HealthIsNeverRateLimited(t *testing.T) {
	s := newTestServer()
	s.limiter = ratelimit.New(1, 1)
	for i := 0; i < 20; i++ {
		req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		req.RemoteAddr = "203.0.113.7:6666"
		rec := httptest.NewRecorder()
		s.routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("health check %d got %d, a probe throttled during a spike takes the process out of rotation", i, rec.Code)
		}
	}
}

func TestRoutes_RateLimitIsPerClientAddress(t *testing.T) {
	s := newTestServer()
	s.limiter = ratelimit.New(1, 1)

	call := func(addr string) int {
		req := httptest.NewRequest(http.MethodGet, "/agents", nil)
		req.RemoteAddr = addr
		rec := httptest.NewRecorder()
		s.routes().ServeHTTP(rec, req)
		return rec.Code
	}

	if got := call("203.0.113.7:1"); got == http.StatusTooManyRequests {
		t.Fatal("first client refused immediately")
	}
	if got := call("198.51.100.4:1"); got == http.StatusTooManyRequests {
		t.Fatal("a second client was refused because the first spent its token")
	}
	if got := call("203.0.113.7:2"); got != http.StatusTooManyRequests {
		t.Fatalf("the first client got %d on its second request, want 429", got)
	}
}

func TestRoutes_RateLimitRejectionsAreCounted(t *testing.T) {
	s := newTestServer()
	s.limiter = ratelimit.New(1, 1)
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodGet, "/agents", nil)
		req.RemoteAddr = "203.0.113.7:7777"
		s.routes().ServeHTTP(httptest.NewRecorder(), req)
	}

	rec := httptest.NewRecorder()
	s.metricsReg.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(rec.Body.String(), "nia_rate_limited_total") {
		t.Fatalf("nia_rate_limited_total missing from /metrics:\n%s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "nia_rate_limited_total 0") {
		t.Fatalf("nia_rate_limited_total is 0 after four refusals:\n%s", rec.Body.String())
	}
}

// TestRoutes_NilLimiterIsDisabled keeps every other test in this package
// meaningful: they build servers directly and leave the limiter nil.
func TestRoutes_NilLimiterIsDisabled(t *testing.T) {
	s := newTestServer()
	if s.limiter != nil {
		t.Fatal("newTestServer set a limiter, this test is checking the nil case")
	}
	for i := 0; i < 200; i++ {
		req := httptest.NewRequest(http.MethodGet, "/agents", nil)
		req.RemoteAddr = "203.0.113.7:8888"
		rec := httptest.NewRecorder()
		s.routes().ServeHTTP(rec, req)
		if rec.Code == http.StatusTooManyRequests {
			t.Fatalf("request %d refused by a nil limiter", i)
		}
	}
}
