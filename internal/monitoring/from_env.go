package monitoring

import (
	"context"
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

// envRiskDatabaseURL is the env var that decides whether the running
// cumulative risk total behind Monitor's thresholds is private to one
// process or shared. Unset means InMemoryRiskStore, same "runs out of
// the box, opt into the shared version" posture as
// credentials.FromEnv and audit.FromEnv. A separate variable from
// NIA_AUDIT_DATABASE_URL and NIA_CREDENTIALS_DATABASE_URL on purpose, a
// deployment can point all three at the same Postgres instance
// (deployments/docker-compose.yml does, see the comment there) or keep
// them apart, this package doesn't assume which.
const envRiskDatabaseURL = "NIA_RISK_DATABASE_URL"

// RiskStoreFromEnv builds the RiskStore cmd/gateway actually runs
// against. Takes a context for the same reason credentials.FromEnv
// does: standing up a Postgres-backed store means a real connection and
// a schema check before this can return, better to fail at startup than
// on the first Accumulate call nobody's watching for.
func RiskStoreFromEnv(ctx context.Context) (RiskStore, error) {
	dsn := strings.TrimSpace(os.Getenv(envRiskDatabaseURL))
	if dsn == "" {
		return NewInMemoryRiskStore(), nil
	}
	store, err := NewPostgresRiskStore(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("monitoring: %w", err)
	}
	return store, nil
}
