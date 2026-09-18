package ratelimit

import "testing"

func clearEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{EnvPerClientRPS, EnvPerClientBurst, EnvPerAgentRPS, EnvPerAgentBurst, EnvTrustForwardedFor} {
		t.Setenv(k, "")
	}
}

func TestFromEnv_UnsetUsesTheDefaultsAndIsEnabled(t *testing.T) {
	clearEnv(t)
	cfg, err := FromEnv()
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if cfg.PerClientRPS != DefaultPerClientRPS || cfg.PerAgentRPS != DefaultPerAgentRPS {
		t.Fatalf("got %+v, want the documented defaults", cfg)
	}
	// The whole point of defaulting on: an unset rate limiter must still
	// limit. This is the one FromEnv in this codebase that does not
	// default to off, see the package's own comment for why.
	if !cfg.PerClient().Enabled() || !cfg.PerAgent().Enabled() {
		t.Fatal("a limiter built from unset environment is disabled, rate limiting must not be opt-in")
	}
	if cfg.TrustForwardedFor {
		t.Fatal("TrustForwardedFor defaults to true, the header is attacker-controlled")
	}
}

func TestFromEnv_ExplicitZeroDisables(t *testing.T) {
	clearEnv(t)
	t.Setenv(EnvPerClientRPS, "0")
	t.Setenv(EnvPerAgentRPS, "0")
	cfg, err := FromEnv()
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if cfg.PerClient().Enabled() || cfg.PerAgent().Enabled() {
		t.Fatal("an explicit 0 did not disable the limiter, that is the documented opt out")
	}
}

func TestFromEnv_ExplicitValuesAreUsed(t *testing.T) {
	clearEnv(t)
	t.Setenv(EnvPerClientRPS, "7.5")
	t.Setenv(EnvPerClientBurst, "15")
	t.Setenv(EnvPerAgentRPS, "3")
	t.Setenv(EnvPerAgentBurst, "6")
	t.Setenv(EnvTrustForwardedFor, "1")
	cfg, err := FromEnv()
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if cfg.PerClientRPS != 7.5 || cfg.PerClientBurst != 15 || cfg.PerAgentRPS != 3 || cfg.PerAgentBurst != 6 {
		t.Fatalf("got %+v, want the configured values", cfg)
	}
	if !cfg.TrustForwardedFor {
		t.Fatal("TrustForwardedFor = false with the variable set to 1")
	}
}

func TestFromEnv_RejectsNonsense(t *testing.T) {
	cases := []struct{ key, val string }{
		{EnvPerClientRPS, "fast"},
		{EnvPerClientRPS, "-1"},
		{EnvPerClientBurst, "many"},
		{EnvPerClientBurst, "-5"},
		{EnvPerAgentRPS, "-0.5"},
		{EnvPerAgentBurst, "lots"},
	}
	for _, c := range cases {
		clearEnv(t)
		t.Setenv(c.key, c.val)
		if _, err := FromEnv(); err == nil {
			t.Fatalf("%s=%q was accepted, a typo'd rate limit should fail at startup rather than during the incident it was for", c.key, c.val)
		}
	}
}

func TestFromEnv_OnlyExactlyOneEnablesForwardedTrust(t *testing.T) {
	for _, v := range []string{"true", "yes", "0", " 1"} {
		clearEnv(t)
		t.Setenv(EnvTrustForwardedFor, v)
		cfg, err := FromEnv()
		if err != nil {
			t.Fatalf("FromEnv: %v", err)
		}
		if cfg.TrustForwardedFor {
			t.Fatalf("%s=%q enabled forwarded-header trust, only \"1\" should", EnvTrustForwardedFor, v)
		}
	}
}
