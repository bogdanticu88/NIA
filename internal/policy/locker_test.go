package policy

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
)

// lockerTestClient builds a client against a fake Tessera that answers
// "not found" on GET and succeeds on onboard, the shape these tests need
// so a failure is about locking rather than about the wire format. The
// returned func reports how many requests the fake server has seen.
func lockerTestClient(t *testing.T) (*TesseraHTTPClient, func() int) {
	t.Helper()
	var mu sync.Mutex
	var calls int
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		mu.Unlock()
		switch {
		case r.Method == http.MethodGet:
			writeJSON(w, http.StatusNotFound, getClientResultWire{Outcome: "not_found"})
		default:
			writeJSON(w, http.StatusOK, onboardResultWire{Success: true})
		}
	})
	return c, func() int {
		mu.Lock()
		defer mu.Unlock()
		return calls
	}
}

func TestNoopLocker_ReleasesWithoutError(t *testing.T) {
	release, err := NoopLocker{}.Lock(context.Background(), "agent:x")
	if err != nil {
		t.Fatalf("NoopLocker.Lock: %v", err)
	}
	release()
	// Calling it twice must not panic: a caller that defers the release
	// and also releases early on an error path is a shape worth
	// surviving.
	release()
}

// recordingLocker proves the client takes the lock, and takes it for the
// right key, without needing a database.
type recordingLocker struct {
	mu       sync.Mutex
	locked   []string
	released int
	err      error
}

func (l *recordingLocker) Lock(_ context.Context, key string) (func(), error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err != nil {
		return nil, l.err
	}
	l.locked = append(l.locked, key)
	return func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		l.released++
	}, nil
}

func TestWriteGrants_TakesTheSharedLockForTheAgent(t *testing.T) {
	c, _ := lockerTestClient(t)

	rec := &recordingLocker{}
	c.SetLocker(rec)

	if err := c.WriteGrants(context.Background(), "agent:billing", []Grant{GrantForTool("invoice.read")}); err != nil {
		t.Fatalf("WriteGrants: %v", err)
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.locked) != 1 || rec.locked[0] != "agent:billing" {
		t.Fatalf("locked = %v, want exactly one lock on agent:billing", rec.locked)
	}
	if rec.released != 1 {
		t.Fatalf("released = %d, want 1: a held lock blocks every other replica's grant writes for that agent", rec.released)
	}
}

func TestDeleteGrants_TakesTheSharedLockForTheAgent(t *testing.T) {
	c, _ := lockerTestClient(t)

	rec := &recordingLocker{}
	c.SetLocker(rec)

	if err := c.DeleteGrants(context.Background(), "agent:billing", []Grant{GrantForTool("invoice.read")}); err != nil {
		t.Fatalf("DeleteGrants: %v", err)
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.locked) != 1 || rec.locked[0] != "agent:billing" {
		t.Fatalf("locked = %v, want exactly one lock on agent:billing", rec.locked)
	}
	if rec.released != 1 {
		t.Fatalf("released = %d, want 1", rec.released)
	}
}

// TestWriteGrants_LockFailureIsAnError is the important direction:
// proceeding without the lock would silently be the unserialized
// behaviour the lock exists to prevent, which is worse than failing.
func TestWriteGrants_LockFailureIsAnError(t *testing.T) {
	c, calls := lockerTestClient(t)

	lockErr := errors.New("lock database unreachable")
	c.SetLocker(&recordingLocker{err: lockErr})

	before := calls()
	err := c.WriteGrants(context.Background(), "agent:billing", []Grant{GrantForTool("invoice.read")})
	if err == nil {
		t.Fatal("WriteGrants succeeded without the shared lock")
	}
	if !errors.Is(err, lockErr) {
		t.Fatalf("err = %v, want it to wrap the lock failure", err)
	}
	if got := calls(); got != before {
		t.Fatalf("%d requests reached Tessera after the lock failed, want none", got-before)
	}
}

func TestClient_NoLockerConfiguredStillWorks(t *testing.T) {
	// The default for every existing caller and test: no shared lock,
	// which is correct for a single replica.
	c, _ := lockerTestClient(t)

	if err := c.WriteGrants(context.Background(), "agent:billing", []Grant{GrantForTool("invoice.read")}); err != nil {
		t.Fatalf("WriteGrants with no locker: %v", err)
	}
}

func TestLockerFromEnv(t *testing.T) {
	l, shared, err := LockerFromEnv(context.Background(), func(string) string { return "" })
	if err != nil {
		t.Fatalf("LockerFromEnv: %v", err)
	}
	if shared {
		t.Fatal("shared = true with no DSN configured")
	}
	if _, ok := l.(NoopLocker); !ok {
		t.Fatalf("got %T, want NoopLocker", l)
	}

	if _, _, err := LockerFromEnv(context.Background(), func(string) string {
		return "postgres://nobody:nobody@127.0.0.1:1/nia?sslmode=disable&connect_timeout=1"
	}); err == nil {
		t.Fatal("an unreachable lock database was accepted, it should fail rather than silently fall back to no locking")
	}
}
