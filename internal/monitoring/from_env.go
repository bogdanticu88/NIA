package monitoring

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// The three threshold env vars this file reads. Same "unset means off"
// discipline as policy.FromEnv and audit.FromEnv, but the meaning of
// "off" here is different and matters more: a zero-value Threshold is
// not inert, score.Value >= 0 is true for every non-negative score, so
// it would flag, or worse kill, every single call. ThresholdsFromEnv
// reports whether anything was actually set precisely so the caller
// (cmd/gateway) can tell "run with these thresholds" apart from "don't
// run monitoring at all" rather than defaulting to the dangerous zero
// value.
const (
	envFlagAt   = "NIA_RISK_FLAG_AT"
	envRevokeAt = "NIA_RISK_REVOKE_AT"
	envKillAt   = "NIA_RISK_KILL_AT"
)

// ThresholdsFromEnv reads the three threshold env vars. configured is
// false when none of them are set; the caller must treat that as "skip
// monitoring entirely," not as "run it with every threshold at zero."
func ThresholdsFromEnv() (t Threshold, configured bool, err error) {
	fields := map[string]*float64{
		envFlagAt:   &t.FlagAt,
		envRevokeAt: &t.RevokeAt,
		envKillAt:   &t.KillAt,
	}
	for name, dst := range fields {
		raw := strings.TrimSpace(os.Getenv(name))
		if raw == "" {
			continue
		}
		configured = true
		v, parseErr := strconv.ParseFloat(raw, 64)
		if parseErr != nil {
			return Threshold{}, false, fmt.Errorf("monitoring: %s: %w", name, parseErr)
		}
		*dst = v
	}
	return t, configured, nil
}
