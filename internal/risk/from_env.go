package risk

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// The environment variables that configure behavioural history and rate
// detection.
//
// NIA_RISK_HISTORY_DATABASE_URL unset means InMemoryCallHistory, this
// process's own baseline, lost on restart, same in-memory-by-default
// posture as every other FromEnv in this codebase. Set it to the same
// database every gateway replica points at and "has this agent ever
// called this tool" has one answer instead of one per replica, see
// PostgresCallHistory's own doc comment for why that matters more than
// it sounds.
//
// The two rate variables have to be set together or not at all. Neither
// has a default on purpose: a threshold nobody picked for their own
// traffic either never fires or fires on every busy agent, and what it
// feeds is internal/monitoring's cumulative total, which can kill an
// agent outright. An operator choosing the numbers is the point.
const (
	envHistoryDatabaseURL = "NIA_RISK_HISTORY_DATABASE_URL"
	envRateWindow         = "NIA_RISK_RATE_WINDOW"
	envRateThreshold      = "NIA_RISK_RATE_THRESHOLD"
)

// CallHistoryFromEnv returns the CallHistory this process should score
// against, plus whether it is the shared one, so a caller can log which
// of the two it got rather than leaving an operator to guess.
func CallHistoryFromEnv(ctx context.Context) (history CallHistory, shared bool, err error) {
	dsn := strings.TrimSpace(os.Getenv(envHistoryDatabaseURL))
	if dsn == "" {
		return NewInMemoryCallHistory(), false, nil
	}
	pg, err := NewPostgresCallHistory(ctx, dsn)
	if err != nil {
		// Deliberately not a fallback to the in-memory history: a
		// deployment that set this variable wants a shared baseline,
		// and quietly giving it a private one would look identical
		// while scoring differently, the same reasoning
		// internal/audit's FromEnv gives for refusing to fall back.
		return nil, false, err
	}
	return pg, true, nil
}

// RateConfigFromEnv reads the window and threshold for the call_rate
// signal. Returns (0, 0, nil) when neither variable is set, which
// disables rate tracking, and an error when exactly one is set: that is
// a deployment that meant to turn this on and typo'd, and silently
// leaving it off is how a control plane ends up not detecting the thing
// someone believed it was detecting.
func RateConfigFromEnv() (window time.Duration, threshold int, err error) {
	rawWindow := strings.TrimSpace(os.Getenv(envRateWindow))
	rawThreshold := strings.TrimSpace(os.Getenv(envRateThreshold))
	switch {
	case rawWindow == "" && rawThreshold == "":
		return 0, 0, nil
	case rawWindow == "":
		return 0, 0, fmt.Errorf("risk: %s is set but %s is not, both are required to enable rate detection", envRateThreshold, envRateWindow)
	case rawThreshold == "":
		return 0, 0, fmt.Errorf("risk: %s is set but %s is not, both are required to enable rate detection", envRateWindow, envRateThreshold)
	}

	window, err = time.ParseDuration(rawWindow)
	if err != nil {
		return 0, 0, fmt.Errorf("risk: %s is not a valid duration (try 60s or 1m): %w", envRateWindow, err)
	}
	if window <= 0 {
		return 0, 0, fmt.Errorf("risk: %s must be positive, got %q", envRateWindow, rawWindow)
	}
	threshold, err = strconv.Atoi(rawThreshold)
	if err != nil {
		return 0, 0, fmt.Errorf("risk: %s is not a number: %w", envRateThreshold, err)
	}
	if threshold <= 0 {
		return 0, 0, fmt.Errorf("risk: %s must be positive, got %q", envRateThreshold, rawThreshold)
	}
	return window, threshold, nil
}
