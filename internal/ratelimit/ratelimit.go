// Package ratelimit is the thing NIA had a detection signal for and no
// enforcement of: refusing a request because it arrived too fast.
//
// internal/risk's call_rate signal notices a burst and feeds it into the
// cumulative total internal/monitoring acts on, which is detection with
// containment behind it, not prevention. Nothing in the request path
// said no. docs/THREAT_MODEL.md's threat 10 said so directly, "no rate
// limiting exists anywhere in cmd/gateway", and this is that gap.
//
// Two distinct jobs, which is why callers use it twice with different
// keys. Keyed by client address it protects the surface in front of
// authentication, where a flood of uncredentialed requests costs a
// credential store lookup each and is never even audited (there is no
// resolved identity to attribute an event to). Keyed by agent ref,
// after identity resolution, it caps what one authenticated agent can
// do regardless of how many connections it opens.
//
// Deliberately in-process. A shared limiter would mean a database round
// trip on the hot path to defend against load, which is the wrong trade
// in the exact situation it is meant to help. The honest consequence,
// stated here rather than discovered: with N gateway replicas behind a
// load balancer, the effective ceiling is N times the configured rate.
// Pick the per-replica number accordingly, and treat this as a blast
// shield, not a quota system.
package ratelimit

import (
	"sync"
	"time"
)

// defaultMaxKeys bounds how many distinct keys are tracked at once.
// This matters more than it looks: the key for the pre-auth limiter is
// a client address, an attacker picks those, and an unbounded map keyed
// by attacker-controlled input is itself the denial of service this
// package exists to prevent.
const defaultMaxKeys = 16384

// bucket is one key's token bucket. tokens is a float because refill is
// continuous: at 2.5 requests per second a bucket gains 2.5 tokens per
// second, not 2, and rounding that down would quietly enforce a
// different rate than the one configured.
type bucket struct {
	tokens   float64
	lastFill time.Time
	lastSeen time.Time
}

// Limiter is a token bucket per key. Zero rate means the limiter is
// disabled and Allow always returns true, which is what an unset
// configuration produces, see FromEnv.
type Limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket

	rate    float64 // tokens added per second
	burst   float64 // bucket capacity, the most that can arrive at once
	idleTTL time.Duration
	maxKeys int

	// now is swappable so tests can advance time without sleeping.
	// Refill is computed from elapsed time rather than from a ticker
	// precisely so this is possible and so a paused process doesn't
	// accumulate a burst it never earned.
	now func() time.Time
}

// New builds a limiter allowing rate requests per second per key, with
// burst as the bucket's capacity. A rate of zero or less disables it
// entirely: Allow returns true for everything and no state is kept.
// burst below 1 is raised to 1, a bucket that cannot hold a single
// token would reject every request including the first.
func New(rate float64, burst int) *Limiter {
	b := float64(burst)
	if b < 1 {
		b = 1
	}
	return &Limiter{
		buckets: make(map[string]*bucket),
		rate:    rate,
		burst:   b,
		idleTTL: 10 * time.Minute,
		maxKeys: defaultMaxKeys,
		now:     time.Now,
	}
}

// Enabled reports whether this limiter actually limits anything. A nil
// limiter and a zero-rate limiter are both disabled, so a caller can
// hold a nil *Limiter and still call Allow.
func (l *Limiter) Enabled() bool {
	return l != nil && l.rate > 0
}

// Allow takes one token for key and reports whether it was available.
// A disabled limiter always allows.
func (l *Limiter) Allow(key string) bool {
	if !l.Enabled() {
		return true
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= l.maxKeys {
			l.evictLocked(now)
		}
		b = &bucket{tokens: l.burst, lastFill: now}
		l.buckets[key] = b
	} else {
		elapsed := now.Sub(b.lastFill).Seconds()
		if elapsed > 0 {
			b.tokens += elapsed * l.rate
			if b.tokens > l.burst {
				b.tokens = l.burst
			}
			b.lastFill = now
		}
	}
	b.lastSeen = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// evictLocked frees room in the key table. Idle buckets go first, which
// is the ordinary case, a key that has not been seen within idleTTL has
// a full bucket anyway and dropping it changes nothing observable.
//
// If that frees nothing, the table is full of currently-active keys,
// which is either real traffic from very many clients or an attacker
// cycling addresses. Then the oldest-seen half goes. Evicting rather
// than refusing on principle: a full table must not become a way to get
// legitimate callers denied, so this degrades toward "some attackers
// get a fresh bucket" instead of "everyone gets rejected."
func (l *Limiter) evictLocked(now time.Time) {
	for k, b := range l.buckets {
		if now.Sub(b.lastSeen) > l.idleTTL {
			delete(l.buckets, k)
		}
	}
	if len(l.buckets) < l.maxKeys {
		return
	}
	target := len(l.buckets) / 2
	var oldest time.Time
	for _, b := range l.buckets {
		if oldest.IsZero() || b.lastSeen.Before(oldest) {
			oldest = b.lastSeen
		}
	}
	cutoff := oldest.Add(now.Sub(oldest) / 2)
	for k, b := range l.buckets {
		if len(l.buckets) <= target {
			break
		}
		if !b.lastSeen.After(cutoff) {
			delete(l.buckets, k)
		}
	}
}

// Tracked reports how many keys currently have a bucket. Exported for
// tests and for the metric cmd/api and cmd/gateway expose, not part of
// the limiting decision.
func (l *Limiter) Tracked() int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}
