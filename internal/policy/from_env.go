package policy

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// Environment variables FromEnv reads. Prefixed NIA_TESSERA_ rather than
// just TESSERA_ because these configure NIA's client of Tessera, not
// Tessera itself, cmd/api and cmd/gateway run in a different process
// (often a different container) than Tessera.Service and the two don't
// share an environment.
const (
	envBaseURL       = "NIA_TESSERA_BASE_URL"
	envSigningKey    = "NIA_TESSERA_JWT_SIGNING_KEY"
	envIssuer        = "NIA_TESSERA_JWT_ISSUER"
	envAudience      = "NIA_TESSERA_JWT_AUDIENCE"
	envSystemSubject = "NIA_TESSERA_SYSTEM_SUBJECT"
)

// defaultIssuer and defaultAudience match Tessera.Service's own Program.cs
// defaults (TESSERA_JWT_ISSUER / TESSERA_JWT_AUDIENCE, both optional
// there too), so a local dev setup that leaves both sides at their
// defaults still matches without anyone having to set four env vars
// instead of two.
const (
	defaultIssuer        = "tessera"
	defaultAudience      = "tessera-clients"
	defaultSystemSubject = "nia-system"
)

// FromEnv builds the Client cmd/api and cmd/gateway actually run against,
// picked by environment rather than hardcoded in either binary, the same
// "runs out of the box, swap in the real thing later" pattern Tessera
// itself uses for IAuthorizationStore and IClientRegistry.
//
// NIA_TESSERA_BASE_URL unset (the default) means InMemoryClient, no
// Tessera, no network calls, nothing else needs to be running. Setting it
// switches to TesseraHTTPClient, and at that point NIA_TESSERA_JWT_SIGNING_KEY
// becomes required, fail fast on a real deployment pointed at a real
// service with no shared secret configured is much better than fail
// silent on the first authenticated call. It must decode as base64 and be
// the exact same key Tessera.Service was started with
// (TESSERA_JWT_SIGNING_KEY there), this is a shared secret, not something
// NIA generates or negotiates.
func FromEnv() (Client, error) {
	baseURL := strings.TrimSpace(os.Getenv(envBaseURL))
	if baseURL == "" {
		return NewInMemoryClient(), nil
	}

	// Trim before both the emptiness check and the decode, not just the
	// check, a value with incidental leading or trailing whitespace (an
	// .env parser that doesn't strip around '=', a trailing space from a
	// copy-paste) would otherwise pass the "is it set" check here and
	// then fail base64 decoding with a confusing error that makes a
	// perfectly valid key look invalid.
	signingKeyB64 := strings.TrimSpace(os.Getenv(envSigningKey))
	if signingKeyB64 == "" {
		return nil, fmt.Errorf("policy: %s is set but %s is not, both are required to talk to a real Tessera instance", envBaseURL, envSigningKey)
	}
	signingKey, err := base64.StdEncoding.DecodeString(signingKeyB64)
	if err != nil {
		return nil, fmt.Errorf("policy: %s is not valid base64: %w", envSigningKey, err)
	}

	issuer := envOrDefault(envIssuer, defaultIssuer)
	audience := envOrDefault(envAudience, defaultAudience)
	systemSubject := envOrDefault(envSystemSubject, defaultSystemSubject)

	httpClient := &http.Client{Timeout: 10 * time.Second}
	client, err := NewTesseraHTTPClient(baseURL, httpClient, signingKey, issuer, audience, systemSubject)
	if err != nil {
		return nil, fmt.Errorf("policy: building the tessera client: %w", err)
	}
	return client, nil
}

func envOrDefault(name, def string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return def
}
