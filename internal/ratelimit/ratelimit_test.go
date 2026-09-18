package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// fixedClock lets these tests advance time exactly rather than sleeping,
// which is what makes refill assertions deterministic: a test that
// sleeps 100ms and expects exactly one token back is a flake waiting for
// a loaded CI machine.
type fixedClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fixedClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fixedClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func newTestLimiter(rate float64, burst int) (*Limiter, *fixedClock) {
	clock := &fixedClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	l := New(rate, burst)
	l.now = clock.Now
	return l, clock
}

func TestLimiter_AllowsUpToBurstThenRefuses(t *testing.T) {
	l, _ := newTestLimiter(1, 3)
	for i := 0; i < 3; i++ {
		if !l.Allow("a") {
			t.Fatalf("request %d was refused inside the burst of 3", i+1)
		}
	}
	if l.Allow("a") {
		t.Fatal("the fourth request was allowed with a burst of 3 and no time passed")
	}
}

func TestLimiter_RefillsOverTime(t *testing.T) {
	l, clock := newTestLimiter(2, 2) // two per second
	if !l.Allow("a") || !l.Allow("a") {
		t.Fatal("the burst itself was refused")
	}
	if l.Allow("a") {
		t.Fatal("allowed past the burst with no time passed")
	}

	clock.Advance(500 * time.Millisecond) // one token at 2/s
	if !l.Allow("a") {
		t.Fatal("refused after enough time for exactly one token")
	}
	if l.Allow("a") {
		t.Fatal("allowed twice for one token's worth of time")
	}
}

// TestLimiter_FractionalRateIsNotRoundedDown guards the reason tokens
// are a float: at 2.5 per second, five seconds must yield twelve
// refills, not ten.
func TestLimiter_FractionalRateIsNotRoundedDown(t *testing.T) {
	l, clock := newTestLimiter(2.5, 1)
	if !l.Allow("a") {
		t.Fatal("first request refused")
	}
	clock.Advance(400 * time.Millisecond) // exactly one token at 2.5/s
	if !l.Allow("a") {
		t.Fatal("refused after 400ms at 2.5 per second, the rate is being rounded down")
	}
}

func TestLimiter_DoesNotAccumulatePastBurst(t *testing.T) {
	l, clock := newTestLimiter(10, 2)
	clock.Advance(time.Hour) // an hour of idle time, far more than the burst
	if !l.Allow("a") || !l.Allow("a") {
		t.Fatal("the burst was refused after idling")
	}
	if l.Allow("a") {
		t.Fatal("an idle bucket accumulated more than its burst, an hour of silence should not buy a flood")
	}
}

func TestLimiter_KeysAreIndependent(t *testing.T) {
	l, _ := newTestLimiter(1, 1)
	if !l.Allow("a") {
		t.Fatal("first key refused")
	}
	if !l.Allow("b") {
		t.Fatal("a second key was refused because the first had spent its token")
	}
	if l.Allow("a") {
		t.Fatal("the first key was allowed a second request")
	}
}

func TestLimiter_ZeroRateIsDisabled(t *testing.T) {
	l := New(0, 0)
	if l.Enabled() {
		t.Fatal("Enabled = true for a zero rate")
	}
	for i := 0; i < 1000; i++ {
		if !l.Allow("a") {
			t.Fatalf("a disabled limiter refused request %d", i)
		}
	}
	if l.Tracked() != 0 {
		t.Fatalf("a disabled limiter is tracking %d keys, it should keep no state", l.Tracked())
	}
}

// TestLimiter_NilIsDisabled matters because both binaries' tests build
// their server structs directly and leave the limiters nil, and because
// a nil limiter must never panic on the hot path.
func TestLimiter_NilIsDisabled(t *testing.T) {
	var l *Limiter
	if l.Enabled() {
		t.Fatal("a nil limiter reports Enabled")
	}
	if !l.Allow("a") {
		t.Fatal("a nil limiter refused a request")
	}
	if l.Tracked() != 0 {
		t.Fatal("a nil limiter reports tracked keys")
	}
}

func TestLimiter_BurstBelowOneIsRaised(t *testing.T) {
	// A bucket that cannot hold one token would refuse everything,
	// including the very first request, which is never what someone
	// configuring "burst 0" means.
	l, _ := newTestLimiter(1, 0)
	if !l.Allow("a") {
		t.Fatal("a burst of 0 refused the first request instead of being raised to 1")
	}
}

// TestLimiter_KeyTableIsBounded is the self-inflicted denial of service
// this has to avoid: the pre-auth key is a client address, an attacker
// picks those, and an unbounded map keyed by attacker input is itself
// the attack.
func TestLimiter_KeyTableIsBounded(t *testing.T) {
	l, _ := newTestLimiter(100, 100)
	l.maxKeys = 64

	for i := 0; i < 5000; i++ {
		l.Allow(string(rune(i%1114111)) + "-key")
	}
	if got := l.Tracked(); got > l.maxKeys {
		t.Fatalf("tracking %d keys with a cap of %d", got, l.maxKeys)
	}
}

// TestLimiter_EvictionPrefersIdleKeys confirms the cheap case: a key
// nobody has used within the TTL has a full bucket anyway, so dropping
// it changes nothing an active caller can observe.
func TestLimiter_EvictionPrefersIdleKeys(t *testing.T) {
	l, clock := newTestLimiter(100, 100)
	l.maxKeys = 4
	l.idleTTL = time.Minute

	for _, k := range []string{"old-1", "old-2", "old-3"} {
		l.Allow(k)
	}
	clock.Advance(2 * time.Minute) // all three are now idle
	l.Allow("fresh")
	l.Allow("newcomer") // forces an eviction sweep

	if l.Tracked() > l.maxKeys {
		t.Fatalf("tracking %d keys with a cap of %d", l.Tracked(), l.maxKeys)
	}
	// The recently active keys must have survived the sweep.
	l.mu.Lock()
	_, freshKept := l.buckets["fresh"]
	_, newKept := l.buckets["newcomer"]
	l.mu.Unlock()
	if !freshKept || !newKept {
		t.Fatal("eviction dropped an active key while idle ones were available")
	}
}

func TestLimiter_ConcurrentAllowIsRaceFree(t *testing.T) {
	l, _ := newTestLimiter(1000, 1000)
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				l.Allow("shared")
				l.Allow(string(rune('a' + i%26)))
			}
		}(i)
	}
	wg.Wait()
}

// TestLimiter_ExactlyBurstAllowedUnderConcurrency proves the accounting
// holds when the contention is real rather than sequential: 500 callers
// against a burst of 50 and no refill must see exactly 50 succeed.
func TestLimiter_ExactlyBurstAllowedUnderConcurrency(t *testing.T) {
	l, _ := newTestLimiter(0.0001, 50) // effectively no refill during the test
	var wg sync.WaitGroup
	results := make([]bool, 500)
	for i := 0; i < 500; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = l.Allow("one-key")
		}(i)
	}
	wg.Wait()

	allowed := 0
	for _, ok := range results {
		if ok {
			allowed++
		}
	}
	if allowed != 50 {
		t.Fatalf("%d of 500 concurrent requests allowed, want exactly the burst of 50", allowed)
	}
}

func TestClientKey_StripsThePort(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "203.0.113.7:54321"
	if got := ClientKey(r, false); got != "203.0.113.7" {
		t.Fatalf("ClientKey = %q, want the address without the port", got)
	}
}

func TestClientKey_IgnoresForwardedForUnlessTrusted(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "203.0.113.7:54321"
	r.Header.Set("X-Forwarded-For", "198.51.100.1")

	if got := ClientKey(r, false); got != "203.0.113.7" {
		t.Fatalf("ClientKey = %q with trust off, want the real peer address: an attacker sets this header", got)
	}
	if got := ClientKey(r, true); got != "198.51.100.1" {
		t.Fatalf("ClientKey = %q with trust on, want the forwarded address", got)
	}
}

func TestClientKey_TakesTheLeftmostForwardedEntry(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.1:1234"
	r.Header.Set("X-Forwarded-For", " 198.51.100.1 , 10.0.0.5 ")
	if got := ClientKey(r, true); got != "198.51.100.1" {
		t.Fatalf("ClientKey = %q, want the leftmost entry trimmed", got)
	}
}

func TestMiddleware_RefusesWith429AndRetryAfter(t *testing.T) {
	l, _ := newTestLimiter(1, 1)
	var rejected int
	h := Middleware(l, false, func(string) { rejected++ }, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/agents", nil)
		r.RemoteAddr = "203.0.113.7:1111"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec
	}

	if got := req().Code; got != http.StatusOK {
		t.Fatalf("first request status = %d, want 200", got)
	}
	rec := req()
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second request status = %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("no Retry-After header on a 429")
	}
	if rejected != 1 {
		t.Fatalf("onReject called %d times, want 1", rejected)
	}
}

func TestMiddleware_ExemptPathIsNeverLimited(t *testing.T) {
	l, _ := newTestLimiter(1, 1)
	h := Middleware(l, false, nil, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), "/healthz")

	for i := 0; i < 50; i++ {
		r := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		r.RemoteAddr = "203.0.113.7:1111"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		if rec.Code != http.StatusOK {
			t.Fatalf("health check %d was rate limited (status %d), a probe being throttled during a spike takes the process out of rotation", i, rec.Code)
		}
	}
}

func TestMiddleware_DisabledLimiterReturnsTheHandlerUntouched(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	if got := Middleware(New(0, 0), false, nil, inner); got == nil {
		t.Fatal("Middleware returned nil for a disabled limiter")
	}
	for i := 0; i < 200; i++ {
		r := httptest.NewRequest(http.MethodGet, "/agents", nil)
		r.RemoteAddr = "203.0.113.7:1111"
		rec := httptest.NewRecorder()
		Middleware(New(0, 0), false, nil, inner).ServeHTTP(rec, r)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d refused by a disabled limiter", i)
		}
	}
}

func TestMiddleware_LimitsPerClientNotGlobally(t *testing.T) {
	l, _ := newTestLimiter(1, 1)
	h := Middleware(l, false, nil, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	call := func(addr string) int {
		r := httptest.NewRequest(http.MethodGet, "/agents", nil)
		r.RemoteAddr = addr
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec.Code
	}

	if call("203.0.113.7:1") != http.StatusOK {
		t.Fatal("first client refused")
	}
	if got := call("198.51.100.9:1"); got != http.StatusOK {
		t.Fatalf("a second client got %d, one client exhausting its bucket must not affect another", got)
	}
	if got := call("203.0.113.7:2"); got != http.StatusTooManyRequests {
		t.Fatalf("the first client's second request got %d, want 429, a new source port is the same client", got)
	}
}
