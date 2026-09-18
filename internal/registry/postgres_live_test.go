package registry

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/bogdanticu88/nia/internal/identity"
)

func liveRegistry(t *testing.T) (*PostgresAgentRegistry, context.Context) {
	t.Helper()
	dsn := os.Getenv("NIA_REGISTRY_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NIA_REGISTRY_TEST_DATABASE_URL not set, skipping live Postgres test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	r, err := NewPostgresAgentRegistry(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPostgresAgentRegistry: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r, ctx
}

// liveRef keeps runs independent against a shared, long-lived database,
// and each test deletes its own row afterwards. An inventory test that
// leaves rows behind changes what a later List test sees.
func liveRef(t *testing.T, r *PostgresAgentRegistry) string {
	t.Helper()
	ref := fmt.Sprintf("agent:live-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		_, _ = r.db.ExecContext(context.Background(), `DELETE FROM agents WHERE ref = $1`, ref)
	})
	return ref
}

func TestPostgresAgentRegistry_Live(t *testing.T) {
	r, ctx := liveRegistry(t)
	ref := liveRef(t, r)

	agent := identity.AgentRef{
		Ref:          ref,
		DisplayName:  "billing reconciler",
		Owner:        "bogdan",
		BusinessUnit: "finance",
		Assurance:    identity.AssuranceStrong,
		Purpose:      "reconcile invoices",
	}
	if err := r.Register(ctx, agent); err != nil {
		t.Fatalf("Register: %v", err)
	}

	got, err := r.Get(ctx, ref)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.DisplayName != agent.DisplayName || got.Owner != agent.Owner || got.BusinessUnit != agent.BusinessUnit {
		t.Fatalf("got %+v, want the fields it was registered with", got)
	}
	if got.Assurance != identity.AssuranceStrong {
		t.Fatalf("Assurance = %v, want strong: the column round trip lost it", got.Assurance)
	}
	if got.State != identity.StateActive {
		t.Fatalf("State = %q, want active by default", got.State)
	}
	if got.RegisteredAt.IsZero() {
		t.Fatal("RegisteredAt is zero after a round trip")
	}
	if got.KilledAt != nil {
		t.Fatalf("KilledAt = %v on a never-killed agent, want nil rather than a zero time", got.KilledAt)
	}
}

func TestPostgresAgentRegistry_Live_DuplicateIsRejected(t *testing.T) {
	r, ctx := liveRegistry(t)
	ref := liveRef(t, r)

	if err := r.Register(ctx, identity.AgentRef{Ref: ref}); err != nil {
		t.Fatalf("first Register: %v", err)
	}
	err := r.Register(ctx, identity.AgentRef{Ref: ref})
	if !errors.Is(err, ErrAlreadyRegistered) {
		t.Fatalf("second Register = %v, want ErrAlreadyRegistered", err)
	}
}

// TestPostgresAgentRegistry_Live_DuplicateIsDecidedByTheDatabase is the
// reason Register does not read-then-write: across replicas that leaves
// a window where both see "not registered" and both insert.
func TestPostgresAgentRegistry_Live_DuplicateIsDecidedByTheDatabase(t *testing.T) {
	a, ctx := liveRegistry(t)
	b, _ := liveRegistry(t)
	ref := liveRef(t, a)

	errs := make(chan error, 2)
	for _, reg := range []*PostgresAgentRegistry{a, b} {
		go func(reg *PostgresAgentRegistry) {
			errs <- reg.Register(ctx, identity.AgentRef{Ref: ref})
		}(reg)
	}
	var ok, dup int
	for i := 0; i < 2; i++ {
		switch err := <-errs; {
		case err == nil:
			ok++
		case errors.Is(err, ErrAlreadyRegistered):
			dup++
		default:
			t.Fatalf("Register: %v", err)
		}
	}
	if ok != 1 || dup != 1 {
		t.Fatalf("%d succeeded and %d were rejected as duplicates, want exactly one of each", ok, dup)
	}
}

func TestPostgresAgentRegistry_Live_NotFound(t *testing.T) {
	r, ctx := liveRegistry(t)
	if _, err := r.Get(ctx, "agent:definitely-not-registered"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get = %v, want ErrNotFound", err)
	}
	if err := r.SetState(ctx, "agent:definitely-not-registered", identity.StateKilled); !errors.Is(err, ErrNotFound) {
		t.Fatalf("SetState = %v, want ErrNotFound", err)
	}
}

func TestPostgresAgentRegistry_Live_SetStateRecordsWhenItWasKilled(t *testing.T) {
	r, ctx := liveRegistry(t)
	ref := liveRef(t, r)
	if err := r.Register(ctx, identity.AgentRef{Ref: ref}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := r.SetState(ctx, ref, identity.StateKilled); err != nil {
		t.Fatalf("SetState: %v", err)
	}

	got, err := r.Get(ctx, ref)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.State != identity.StateKilled {
		t.Fatalf("State = %q, want killed", got.State)
	}
	if got.KilledAt == nil {
		t.Fatal("KilledAt is nil after a kill")
	}

	// Restoring leaves KilledAt in place: when it was last killed is
	// still true and still worth having during a review.
	if err := r.SetState(ctx, ref, identity.StateActive); err != nil {
		t.Fatalf("SetState(active): %v", err)
	}
	got, err = r.Get(ctx, ref)
	if err != nil {
		t.Fatalf("Get after restore: %v", err)
	}
	if got.State != identity.StateActive {
		t.Fatalf("State = %q after restore, want active", got.State)
	}
	if got.KilledAt == nil {
		t.Fatal("KilledAt was cleared by a restore, the fact that it was killed is still true")
	}
}

// TestPostgresAgentRegistry_Live_TwoHandlesShareOneInventory is the
// whole reason this implementation exists: with the in-memory registry,
// a second cmd/api replica returned 404 for an agent the first had
// registered.
func TestPostgresAgentRegistry_Live_TwoHandlesShareOneInventory(t *testing.T) {
	first, ctx := liveRegistry(t)
	second, _ := liveRegistry(t)
	ref := liveRef(t, first)

	if err := first.Register(ctx, identity.AgentRef{Ref: ref, Owner: "bogdan"}); err != nil {
		t.Fatalf("Register on the first handle: %v", err)
	}
	got, err := second.Get(ctx, ref)
	if err != nil {
		t.Fatalf("Get on the second handle: %v, the inventory is not shared", err)
	}
	if got.Owner != "bogdan" {
		t.Fatalf("Owner = %q on the second handle", got.Owner)
	}

	// A kill recorded through one is visible through the other.
	if err := second.SetState(ctx, ref, identity.StateKilled); err != nil {
		t.Fatalf("SetState on the second handle: %v", err)
	}
	got, err = first.Get(ctx, ref)
	if err != nil {
		t.Fatalf("Get on the first handle: %v", err)
	}
	if got.State != identity.StateKilled {
		t.Fatalf("State = %q on the first handle, want killed", got.State)
	}
}

func TestPostgresAgentRegistry_Live_ListIncludesRegisteredAgents(t *testing.T) {
	r, ctx := liveRegistry(t)
	ref := liveRef(t, r)
	if err := r.Register(ctx, identity.AgentRef{Ref: ref}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	list, err := r.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	for _, a := range list {
		if a.Ref == ref {
			return
		}
	}
	t.Fatalf("List did not include %s, got %d agents", ref, len(list))
}
