package risk

import (
	"context"
	"testing"
	"time"
)

func TestCallHistoryFromEnv_UnsetReturnsTheInMemoryHistory(t *testing.T) {
	t.Setenv(envHistoryDatabaseURL, "")
	h, shared, err := CallHistoryFromEnv(context.Background())
	if err != nil {
		t.Fatalf("CallHistoryFromEnv: %v", err)
	}
	if shared {
		t.Fatal("shared = true with no database configured")
	}
	if _, ok := h.(*InMemoryCallHistory); !ok {
		t.Fatalf("got %T, want *InMemoryCallHistory", h)
	}
}

func TestCallHistoryFromEnv_UnreachableDatabaseIsAnErrorNotASilentFallback(t *testing.T) {
	// A deployment that set this wants a shared baseline. Quietly handing
	// it a private one would score differently while looking identical.
	t.Setenv(envHistoryDatabaseURL, "postgres://nobody:nobody@127.0.0.1:1/nia?sslmode=disable&connect_timeout=1")
	if _, _, err := CallHistoryFromEnv(context.Background()); err == nil {
		t.Fatal("err = nil for an unreachable database, want an error rather than a fallback to the in-memory history")
	}
}

func TestRateConfigFromEnv_NeitherSetDisablesRateDetection(t *testing.T) {
	t.Setenv(envRateWindow, "")
	t.Setenv(envRateThreshold, "")
	window, threshold, err := RateConfigFromEnv()
	if err != nil {
		t.Fatalf("RateConfigFromEnv: %v", err)
	}
	if window != 0 || threshold != 0 {
		t.Fatalf("got %v, %d, want both zero", window, threshold)
	}
}

func TestRateConfigFromEnv_OneWithoutTheOtherIsAnError(t *testing.T) {
	t.Setenv(envRateWindow, "60s")
	t.Setenv(envRateThreshold, "")
	if _, _, err := RateConfigFromEnv(); err == nil {
		t.Fatalf("%s alone was accepted, want an error rather than rate detection silently staying off", envRateWindow)
	}

	t.Setenv(envRateWindow, "")
	t.Setenv(envRateThreshold, "10")
	if _, _, err := RateConfigFromEnv(); err == nil {
		t.Fatalf("%s alone was accepted, want an error", envRateThreshold)
	}
}

func TestRateConfigFromEnv_BothSetIsParsed(t *testing.T) {
	t.Setenv(envRateWindow, "90s")
	t.Setenv(envRateThreshold, "25")
	window, threshold, err := RateConfigFromEnv()
	if err != nil {
		t.Fatalf("RateConfigFromEnv: %v", err)
	}
	if window != 90*time.Second || threshold != 25 {
		t.Fatalf("got %v, %d, want 90s and 25", window, threshold)
	}
}

func TestRateConfigFromEnv_RejectsNonsenseValues(t *testing.T) {
	cases := []struct{ window, threshold string }{
		{"not-a-duration", "10"},
		{"60s", "not-a-number"},
		{"0s", "10"},
		{"-5s", "10"},
		{"60s", "0"},
		{"60s", "-1"},
	}
	for _, c := range cases {
		t.Setenv(envRateWindow, c.window)
		t.Setenv(envRateThreshold, c.threshold)
		if _, _, err := RateConfigFromEnv(); err == nil {
			t.Fatalf("window=%q threshold=%q was accepted, want an error", c.window, c.threshold)
		}
	}
}
