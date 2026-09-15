package policy

import (
	"context"
	"testing"
)

// TestKillDeniesEvenPriorGrants is the one invariant that matters most
// in this whole system: once an agent is killed, a Check must deny,
// immediately, with no cache to flush. This is Tessera's core guarantee
// and the reason the kill switch is "surgical."
func TestKillDeniesEvenPriorGrants(t *testing.T) {
	ctx := context.Background()
	c := NewInMemoryClient()

	grant := GrantForTool("invoice-api")
	if err := c.WriteGrants(ctx, "agent:x", []Grant{grant}); err != nil {
		t.Fatalf("WriteGrants: %v", err)
	}

	allowed, err := c.Check(ctx, "agent:x", grant)
	if err != nil || !allowed {
		t.Fatalf("expected allow before kill, got allowed=%v err=%v", allowed, err)
	}

	if _, err := c.Kill(ctx, "agent:x", "INC-1", "operator"); err != nil {
		t.Fatalf("Kill: %v", err)
	}

	allowed, err = c.Check(ctx, "agent:x", grant)
	if err != nil {
		t.Fatalf("Check after kill: %v", err)
	}
	if allowed {
		t.Fatal("expected deny immediately after kill, got allow")
	}
}

// TestReconcileNeverResurrectsAKill mirrors Tessera's explicit invariant
// of the same name: writing grants for a killed agent must not silently
// un-kill it.
func TestReconcileNeverResurrectsAKill(t *testing.T) {
	ctx := context.Background()
	c := NewInMemoryClient()

	if _, err := c.Kill(ctx, "agent:x", "INC-1", "operator"); err != nil {
		t.Fatalf("Kill: %v", err)
	}

	err := c.WriteGrants(ctx, "agent:x", []Grant{GrantForTool("invoice-api")})
	if err == nil {
		t.Fatal("expected WriteGrants to fail against a killed agent")
	}

	killed, err := c.IsKilled(ctx, "agent:x")
	if err != nil || !killed {
		t.Fatalf("expected agent to remain killed, killed=%v err=%v", killed, err)
	}
}

func TestRestoreClearsKillSentinel(t *testing.T) {
	ctx := context.Background()
	c := NewInMemoryClient()

	if _, err := c.Kill(ctx, "agent:x", "INC-1", "operator"); err != nil {
		t.Fatalf("Kill: %v", err)
	}
	if err := c.Restore(ctx, "agent:x"); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	killed, err := c.IsKilled(ctx, "agent:x")
	if err != nil || killed {
		t.Fatalf("expected agent restored, killed=%v err=%v", killed, err)
	}

	// Restore does not resurrect grants on its own; caller must
	// re-declare. Confirm that contract.
	grants, err := c.ListGrants(ctx, "agent:x")
	if err != nil {
		t.Fatalf("ListGrants: %v", err)
	}
	if len(grants) != 0 {
		t.Fatalf("expected no grants after restore without re-declaring, got %v", grants)
	}
}
