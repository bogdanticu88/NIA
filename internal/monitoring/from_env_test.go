package monitoring

import "testing"

func clearThresholdEnv(t *testing.T) {
	t.Helper()
	t.Setenv(envFlagAt, "")
	t.Setenv(envRevokeAt, "")
	t.Setenv(envKillAt, "")
}

func TestThresholdsFromEnv_NoneSet_NotConfigured(t *testing.T) {
	clearThresholdEnv(t)
	th, configured, err := ThresholdsFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if configured {
		t.Fatalf("configured = true with nothing set, want false")
	}
	if th != (Threshold{}) {
		t.Fatalf("got %+v, want a zero Threshold when nothing is configured", th)
	}
}

func TestThresholdsFromEnv_OneSet_IsConfiguredWithOthersZero(t *testing.T) {
	clearThresholdEnv(t)
	t.Setenv(envKillAt, "20")
	th, configured, err := ThresholdsFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !configured {
		t.Fatal("configured = false with NIA_RISK_KILL_AT set, want true")
	}
	if th.KillAt != 20 || th.FlagAt != 0 || th.RevokeAt != 0 {
		t.Fatalf("got %+v, want KillAt=20 and the other two at their zero value", th)
	}
}

func TestThresholdsFromEnv_AllSet(t *testing.T) {
	clearThresholdEnv(t)
	t.Setenv(envFlagAt, "5")
	t.Setenv(envRevokeAt, "10")
	t.Setenv(envKillAt, "20")
	th, configured, err := ThresholdsFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !configured {
		t.Fatal("configured = false with all three set, want true")
	}
	if th != (Threshold{FlagAt: 5, RevokeAt: 10, KillAt: 20}) {
		t.Fatalf("got %+v, want {5 10 20}", th)
	}
}

func TestThresholdsFromEnv_UnparseableValue_IsAnError(t *testing.T) {
	clearThresholdEnv(t)
	t.Setenv(envFlagAt, "not-a-number")
	if _, _, err := ThresholdsFromEnv(); err == nil {
		t.Fatal("expected an error for an unparseable threshold, got nil")
	}
}
