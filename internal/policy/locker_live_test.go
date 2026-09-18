package policy

import (
	"context"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"
)

// The live tests for PostgresLocker. Skipped unless
// NIA_POLICY_LOCK_TEST_DATABASE_URL points at a real Postgres, same
// posture as every other live test here, and run in CI against the
// Postgres service container.
//
// A fake cannot stand in for this one. The property being tested is that
// two independent processes serialize against each other through the
// database, and anything that mocks the database mocks away the whole
// mechanism.
func liveLocker(t *testing.T) (*PostgresLocker, context.Context) {
	t.Helper()
	dsn := os.Getenv("NIA_POLICY_LOCK_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NIA_POLICY_LOCK_TEST_DATABASE_URL not set, skipping live Postgres test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	l, err := NewPostgresLocker(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPostgresLocker: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l, ctx
}

func liveKey(t *testing.T) string {
	t.Helper()
	return "agent:lock-live-" + time.Now().Format("20060102T150405.000000000")
}

func TestPostgresLocker_Live(t *testing.T) {
	l, ctx := liveLocker(t)
	release, err := l.Lock(ctx, liveKey(t))
	if err != nil {
		t.Fatalf("Lock: %v", err)
	}
	release()
}

// TestPostgresLocker_Live_TwoHoldersSerialize is the whole point: two
// independent lockers standing in for two replicas, where the second
// must not enter the critical section until the first has left it.
func TestPostgresLocker_Live_TwoHoldersSerialize(t *testing.T) {
	first, ctx := liveLocker(t)
	second, _ := liveLocker(t)
	key := liveKey(t)

	releaseFirst, err := first.Lock(ctx, key)
	if err != nil {
		t.Fatalf("first Lock: %v", err)
	}

	entered := make(chan time.Time, 1)
	go func() {
		release, err := second.Lock(ctx, key)
		if err != nil {
			t.Errorf("second Lock: %v", err)
			close(entered)
			return
		}
		entered <- time.Now()
		release()
	}()

	// The second holder must still be waiting while the first holds it.
	select {
	case at, ok := <-entered:
		if ok {
			t.Fatalf("the second locker entered at %v while the first still held the lock", at)
		}
		t.Fatal("the second locker failed")
	case <-time.After(300 * time.Millisecond):
	}

	releasedAt := time.Now()
	releaseFirst()

	select {
	case at, ok := <-entered:
		if !ok {
			t.Fatal("the second locker failed")
		}
		if at.Before(releasedAt) {
			t.Fatalf("the second locker entered at %v, before the first released at %v", at, releasedAt)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the second locker never acquired the lock after the first released it")
	}
}

func TestPostgresLocker_Live_DifferentKeysDoNotBlockEachOther(t *testing.T) {
	l, ctx := liveLocker(t)

	releaseA, err := l.Lock(ctx, liveKey(t)+"-a")
	if err != nil {
		t.Fatalf("Lock A: %v", err)
	}
	defer releaseA()

	done := make(chan struct{})
	go func() {
		defer close(done)
		release, err := l.Lock(ctx, liveKey(t)+"-b")
		if err != nil {
			t.Errorf("Lock B: %v", err)
			return
		}
		release()
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("locking a different key blocked behind an unrelated held lock, the keys are colliding")
	}
}

// TestPostgresLocker_Live_GrantWritesSerializeAcrossClients is the same
// property one layer up, through the actual client method the lock
// exists to protect, with two TesseraHTTPClient instances standing in
// for two replicas.
func TestPostgresLocker_Live_GrantWritesSerializeAcrossClients(t *testing.T) {
	lockerA, ctx := liveLocker(t)
	lockerB, _ := liveLocker(t)
	key := liveKey(t)

	var mu sync.Mutex
	var inFlight, maxInFlight int

	// The fake Tessera holds each request briefly, so two unserialized
	// writers would overlap and maxInFlight would reach 2.
	handler := func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			writeJSON(w, http.StatusNotFound, getClientResultWire{Outcome: "not_found"})
			return
		}
		mu.Lock()
		inFlight++
		if inFlight > maxInFlight {
			maxInFlight = inFlight
		}
		mu.Unlock()
		time.Sleep(50 * time.Millisecond)
		mu.Lock()
		inFlight--
		mu.Unlock()
		writeJSON(w, http.StatusOK, onboardResultWire{Success: true})
	}

	clientA, srv := newTestClient(t, handler)
	// A second client against the same fake Tessera, standing in for a
	// second replica: separate in-process mutexes, so only the shared
	// lock can serialize them.
	clientB, err := NewTesseraHTTPClient(srv.URL, srv.Client(), testSigningKey(), testIssuer, testAudience, "nia-system")
	if err != nil {
		t.Fatalf("second client: %v", err)
	}
	clientA.SetLocker(lockerA)
	clientB.SetLocker(lockerB)

	var wg sync.WaitGroup
	for _, c := range []*TesseraHTTPClient{clientA, clientB} {
		wg.Add(1)
		go func(c *TesseraHTTPClient) {
			defer wg.Done()
			if err := c.WriteGrants(ctx, key, []Grant{GrantForTool("invoice.read")}); err != nil {
				t.Errorf("WriteGrants: %v", err)
			}
		}(c)
	}
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if maxInFlight > 1 {
		t.Fatalf("%d onboard calls were in flight at once, two replicas writing grants for the same agent must not overlap", maxInFlight)
	}
}
