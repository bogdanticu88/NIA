package ratelimit

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// The environment variables both binaries read.
//
// Unlike most of this codebase's FromEnv constructors, these default to
// on rather than off. The reasoning is the mistake this whole pass
// exists to correct: an unset security control that nobody notices is
// how a control plane ships wide open, and a rate limiter that only
// protects deployments whose operator remembered a variable protects
// almost nobody. The defaults below are set high enough that no
// legitimate control-plane or gateway traffic reaches them, so the
// cost of being wrong about that is low, and 0 is an explicit,
// documented way to turn it off.
const (
	EnvPerClientRPS   = "NIA_RATE_LIMIT_PER_CLIENT_RPS"
	EnvPerClientBurst = "NIA_RATE_LIMIT_PER_CLIENT_BURST"

	// EnvPerAgentRPS and EnvPerAgentBurst apply only in cmd/gateway,
	// after identity resolution, keyed by agent ref rather than by
	// address. That is a genuinely different limit: the per-client one
	// bounds what one network peer can do before anyone knows who it
	// is, this one bounds what one authenticated agent can do no matter
	// how many peers it calls from.
	EnvPerAgentRPS   = "NIA_GATEWAY_RATE_LIMIT_PER_AGENT_RPS"
	EnvPerAgentBurst = "NIA_GATEWAY_RATE_LIMIT_PER_AGENT_BURST"

	// EnvTrustForwardedFor makes the per-client key come from
	// X-Forwarded-For. Off by default because the header is
	// attacker-controlled: on a directly reachable process, trusting it
	// lets anyone mint unlimited buckets by varying one header. Set it
	// only when a proxy that overwrites the header is the only way in.
	EnvTrustForwardedFor = "NIA_RATE_LIMIT_TRUST_FORWARDED_FOR"
)

// Defaults. Both are per replica, see the package doc comment: with N
// replicas the effective ceiling is N times these numbers.
//
// 50 requests per second sustained, with 100 allowed to arrive at once,
// is roughly two orders of magnitude above what an operator driving
// niactl or a normal agent generates, and far below what it takes to
// hurt a process. The per-agent numbers are lower because one agent
// legitimately bursting 200 tool calls a second is already the
// behaviour internal/risk's call_rate signal is meant to flag.
const (
	DefaultPerClientRPS   = 50
	DefaultPerClientBurst = 100
	DefaultPerAgentRPS    = 20
	DefaultPerAgentBurst  = 40
)

// Config is what a binary needs to build its limiters.
type Config struct {
	PerClientRPS        float64
	PerClientBurst      int
	PerAgentRPS         float64
	PerAgentBurst       int
	TrustForwardedFor   bool
	PerClientConfigured bool // an operator set the value explicitly, rather than taking the default
	PerAgentConfigured  bool
}

// FromEnv reads the configuration, applying the defaults above for
// anything unset. An explicit 0 disables that limiter, which is the
// documented way to opt out; a negative or unparseable value is an
// error rather than a silent fallback to the default, because a
// deployment that typo'd a rate limit should find out at startup, not
// during the incident the limit was for.
func FromEnv() (Config, error) {
	cfg := Config{
		PerClientRPS:   DefaultPerClientRPS,
		PerClientBurst: DefaultPerClientBurst,
		PerAgentRPS:    DefaultPerAgentRPS,
		PerAgentBurst:  DefaultPerAgentBurst,
	}

	var err error
	if cfg.PerClientRPS, cfg.PerClientConfigured, err = floatFromEnv(EnvPerClientRPS, DefaultPerClientRPS); err != nil {
		return Config{}, err
	}
	if cfg.PerClientBurst, _, err = intFromEnv(EnvPerClientBurst, DefaultPerClientBurst); err != nil {
		return Config{}, err
	}
	if cfg.PerAgentRPS, cfg.PerAgentConfigured, err = floatFromEnv(EnvPerAgentRPS, DefaultPerAgentRPS); err != nil {
		return Config{}, err
	}
	if cfg.PerAgentBurst, _, err = intFromEnv(EnvPerAgentBurst, DefaultPerAgentBurst); err != nil {
		return Config{}, err
	}
	cfg.TrustForwardedFor = os.Getenv(EnvTrustForwardedFor) == "1"
	return cfg, nil
}

// PerClient builds the address-keyed limiter this config describes.
func (c Config) PerClient() *Limiter { return New(c.PerClientRPS, c.PerClientBurst) }

// PerAgent builds the agent-keyed limiter this config describes.
func (c Config) PerAgent() *Limiter { return New(c.PerAgentRPS, c.PerAgentBurst) }

func floatFromEnv(name string, def float64) (value float64, configured bool, err error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return def, false, nil
	}
	v, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return 0, false, fmt.Errorf("ratelimit: %s is not a number: %w", name, err)
	}
	if v < 0 {
		return 0, false, fmt.Errorf("ratelimit: %s must be zero (disabled) or positive, got %q", name, raw)
	}
	return v, true, nil
}

func intFromEnv(name string, def int) (value int, configured bool, err error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return def, false, nil
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return 0, false, fmt.Errorf("ratelimit: %s is not a number: %w", name, err)
	}
	if v < 0 {
		return 0, false, fmt.Errorf("ratelimit: %s must be zero or positive, got %q", name, raw)
	}
	return v, true, nil
}
