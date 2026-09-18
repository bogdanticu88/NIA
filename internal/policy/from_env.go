package policy

import (
	"context"
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

	// The OpenFGA direct-check variables. Unprefixed by NIA_TESSERA_
	// because they do not configure NIA's client of Tessera, they point
	// NIA at the authorization store underneath it, which is a
	// different service NIA now reads from directly, see
	// OpenFGAChecker's own doc comment for why a hot-path Check cannot
	// honestly be answered from Tessera's declared grant list.
	//
	// NIA_OPENFGA_STORE_ID is the same store id Tessera is configured
	// with (OPENFGA_STORE_ID there), and
	// deployments/bootstrap-openfga.sh prints it. Pointing the two at
	// different stores is a silent misconfiguration, every Check would
	// come back "not allowed" against an empty store and read as an
	// ordinary denial.
	envOpenFGAURL     = "NIA_OPENFGA_API_URL"
	envOpenFGAStoreID = "NIA_OPENFGA_STORE_ID"
	envOpenFGAModelID = "NIA_OPENFGA_AUTHORIZATION_MODEL_ID"
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

	// Both OpenFGA variables set means Check reads live tuples instead
	// of Tessera's declared grant list, see OpenFGAChecker. Neither set
	// is the previous behavior, unchanged. One set without the other is
	// an error rather than a silent fallback: a deployment that meant
	// to turn this on and typo'd one variable would otherwise keep the
	// fail-open this exists to close, and never know.
	openfgaURL := strings.TrimSpace(os.Getenv(envOpenFGAURL))
	openfgaStore := strings.TrimSpace(os.Getenv(envOpenFGAStoreID))
	switch {
	case openfgaURL == "" && openfgaStore == "":
		return client, nil
	case openfgaURL == "":
		return nil, fmt.Errorf("policy: %s is set but %s is not, both are required to check authorization against OpenFGA directly", envOpenFGAStoreID, envOpenFGAURL)
	case openfgaStore == "":
		return nil, fmt.Errorf("policy: %s is set but %s is not, both are required to check authorization against OpenFGA directly", envOpenFGAURL, envOpenFGAStoreID)
	}
	return NewOpenFGAChecker(client, openfgaURL, openfgaStore, strings.TrimSpace(os.Getenv(envOpenFGAModelID))), nil
}

// FromEnvWithLocker is FromEnv plus the cross-process grant lock, which
// only a real TesseraHTTPClient needs: InMemoryClient is a single
// process by definition, and OpenFGAChecker delegates its writes to the
// client it wraps. Returns whether the shared lock is actually
// configured so the caller can log it.
//
// Separate from FromEnv rather than folded into it because acquiring a
// database handle is a side effect a plain constructor should not have,
// and because every existing caller and test of FromEnv should keep
// working unchanged.
func FromEnvWithLocker(ctx context.Context) (Client, bool, error) {
	client, err := FromEnv()
	if err != nil {
		return nil, false, err
	}
	locker, shared, err := LockerFromEnv(ctx, os.Getenv)
	if err != nil {
		return nil, false, err
	}
	switch c := client.(type) {
	case *TesseraHTTPClient:
		c.SetLocker(locker)
	case *OpenFGAChecker:
		if base, ok := c.base.(*TesseraHTTPClient); ok {
			base.SetLocker(locker)
		}
	}
	return client, shared, nil
}

func envOrDefault(name, def string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return def
}
