package policy

import (
	"context"
	"errors"
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

// TestReconcileNeverResurrectsAKill checks the same invariant Tessera
// names explicitly: writing grants for a killed agent must not silently
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
	if err := c.Restore(ctx, "agent:x", "bogdan"); err != nil {
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

func TestInMemoryClient_RestoreRecordsWhoDidIt(t *testing.T) {
	c := NewInMemoryClient()
	ctx := context.Background()
	if _, err := c.Kill(ctx, "agent:billing", "INC-1", "monitoring"); err != nil {
		t.Fatalf("Kill: %v", err)
	}
	if err := c.Restore(ctx, "agent:billing", "bogdan"); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if got := c.RestoredBy("agent:billing"); got != "bogdan" {
		t.Fatalf("RestoredBy = %q, want the operator who restored it", got)
	}
}

func TestInMemoryClient_RestoreRequiresAnOperator(t *testing.T) {
	c := NewInMemoryClient()
	ctx := context.Background()
	if _, err := c.Kill(ctx, "agent:billing", "INC-1", "monitoring"); err != nil {
		t.Fatalf("Kill: %v", err)
	}
	if err := c.Restore(ctx, "agent:billing", "   "); err == nil {
		t.Fatal("Restore with a blank operator succeeded, an unattributed restore is a record an incident review cannot use")
	}
	// And it did not take effect: a refused restore must leave the kill
	// standing rather than half-applying.
	killed, err := c.IsKilled(ctx, "agent:billing")
	if err != nil {
		t.Fatalf("IsKilled: %v", err)
	}
	if !killed {
		t.Fatal("the agent was restored despite the refused operator")
	}
}

func TestInMemoryClient_SetBusinessUnit(t *testing.T) {
	c := NewInMemoryClient()
	ctx := context.Background()
	if err := c.SetBusinessUnit(ctx, "agent:billing", "finance"); err != nil {
		t.Fatalf("SetBusinessUnit: %v", err)
	}
	if got := c.BusinessUnit("agent:billing"); got != "finance" {
		t.Fatalf("BusinessUnit = %q, want finance", got)
	}
}

// TestInMemoryClient_SetBusinessUnitRefusesAKilledAgent matches the rule
// WriteGrants follows: nothing about a killed agent is rewritten until
// it is explicitly restored, so a reconcile cannot quietly bring part of
// it back.
func TestInMemoryClient_SetBusinessUnitRefusesAKilledAgent(t *testing.T) {
	c := NewInMemoryClient()
	ctx := context.Background()
	if _, err := c.Kill(ctx, "agent:billing", "INC-1", "monitoring"); err != nil {
		t.Fatalf("Kill: %v", err)
	}
	if err := c.SetBusinessUnit(ctx, "agent:billing", "finance"); !errors.Is(err, ErrKilled) {
		t.Fatalf("SetBusinessUnit on a killed agent = %v, want ErrKilled", err)
	}
}
