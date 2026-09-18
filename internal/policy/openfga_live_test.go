package policy

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"
)

// The live cross-service test for OpenFGAChecker. Unlike
// tessera_client_live_test.go, which spawns Tessera.Service from a
// checked-out repo, this one expects an already-running pair: a real
// Tessera.Service and the real OpenFGA instance it is configured
// against. Both are easiest to get from containers, see the README's
// Status section for the exact commands this was run with.
//
// Four variables, all required, all skipped-not-failed when absent, the
// same posture every other live test in this repo takes:
//
//	NIA_TESSERA_TEST_BASE_URL     http://127.0.0.1:58090
//	NIA_TESSERA_TEST_SIGNING_KEY  the base64 key Tessera was started with
//	NIA_OPENFGA_TEST_API_URL      http://127.0.0.1:58080
//	NIA_OPENFGA_TEST_STORE_ID     the store id Tessera is configured with
//
// This cannot be replaced by a test against a fake OpenFGA. The whole
// point is that the object name Tessera's GrantTupleMapper builds out of
// a NIA tool grant has to be a name OpenFGA will actually accept and
// store, and a fake server that echoes back whatever it is asked about
// proves nothing about that.
const (
	envLiveTesseraBaseURL    = "NIA_TESSERA_TEST_BASE_URL"
	envLiveTesseraSigningKey = "NIA_TESSERA_TEST_SIGNING_KEY"
	envLiveOpenFGAURL        = "NIA_OPENFGA_TEST_API_URL"
	envLiveOpenFGAStoreID    = "NIA_OPENFGA_TEST_STORE_ID"
)

func liveOpenFGASetup(t *testing.T) (checker *OpenFGAChecker, tessera *TesseraHTTPClient, ctx context.Context) {
	t.Helper()
	baseURL := os.Getenv(envLiveTesseraBaseURL)
	keyB64 := os.Getenv(envLiveTesseraSigningKey)
	fgaURL := os.Getenv(envLiveOpenFGAURL)
	storeID := os.Getenv(envLiveOpenFGAStoreID)
	if baseURL == "" || keyB64 == "" || fgaURL == "" || storeID == "" {
		t.Skipf("skipping live OpenFGA test: set %s, %s, %s and %s to run it", envLiveTesseraBaseURL, envLiveTesseraSigningKey, envLiveOpenFGAURL, envLiveOpenFGAStoreID)
	}
	key, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		t.Fatalf("%s is not valid base64: %v", envLiveTesseraSigningKey, err)
	}
	tessera, err = NewTesseraHTTPClient(baseURL, &http.Client{Timeout: 10 * time.Second}, key, defaultIssuer, defaultAudience, defaultSystemSubject)
	if err != nil {
		t.Fatalf("NewTesseraHTTPClient: %v", err)
	}
	c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return NewOpenFGAChecker(tessera, fgaURL, storeID, ""), tessera, c
}

// liveAgentRef keeps each run's agent distinct, these tests write real
// tuples into a real store and a reused ref would let one run's leftover
// state decide another run's result.
func liveAgentRef(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("agent:live-%d", time.Now().UnixNano())
}

// TestLive_OpenFGAChecker_ToolGrantIsWritableAndCheckable is the
// regression test for a real defect this work found: NIA encoded a tool
// grant as api_group "tool:<name>", which Tessera maps to the OpenFGA
// object "api_group:tool:<name>", and OpenFGA rejects that outright,
// "invalid 'object' field format", because an object id may not contain
// a colon. Nothing caught it before because every test in this package
// ran against a fake HTTP server that accepted any string, and the one
// earlier live stack run onboarded a client with plain api_group
// grants, never a tool or data grant.
//
// The consequence was not cosmetic: against a real Tessera backed by a
// real OpenFGA, no NIA tool or data grant could be written at all.
func TestLive_OpenFGAChecker_ToolGrantIsWritableAndCheckable(t *testing.T) {
	checker, _, ctx := liveOpenFGASetup(t)
	ref := liveAgentRef(t)

	if err := checker.WriteGrants(ctx, ref, []Grant{GrantForTool("invoice.read")}); err != nil {
		t.Fatalf("WriteGrants with a tool grant against real Tessera and real OpenFGA: %v", err)
	}

	allowed, err := checker.Check(ctx, ref, GrantForTool("invoice.read"))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !allowed {
		t.Fatal("Check = false for a tool grant that was just written, the tuple OpenFGA stored is not the tuple this client asks about")
	}

	other, err := checker.Check(ctx, ref, GrantForTool("invoice.delete"))
	if err != nil {
		t.Fatalf("Check for an ungranted tool: %v", err)
	}
	if other {
		t.Fatal("Check = true for a tool that was never granted")
	}
}

func TestLive_OpenFGAChecker_DataGrantIsWritableAndCheckable(t *testing.T) {
	checker, _, ctx := liveOpenFGASetup(t)
	ref := liveAgentRef(t)

	if err := checker.WriteGrants(ctx, ref, []Grant{GrantForData("customers.ssn")}); err != nil {
		t.Fatalf("WriteGrants with a data grant: %v", err)
	}
	allowed, err := checker.Check(ctx, ref, GrantForData("customers.ssn"))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !allowed {
		t.Fatal("Check = false for a data grant that was just written")
	}
}

// TestLive_OpenFGAChecker_RestoreDoesNotResurrectAuthorization is the
// fail-open this whole type exists to close, proven against the real
// pair rather than argued from source. Tessera's Kill deletes a client's
// OpenFGA tuples but leaves its declared grant list alone, and Restore
// clears the kill sentinel without rewriting them. Reading the declared
// list, which is all Tessera's HTTP surface exposes, a restored agent
// looks authorized. Reading OpenFGA, it is not, because nothing has
// written a tuple back yet.
//
// Both halves are asserted here in one test on purpose: the divergence
// is the finding, and checking only one side would not show it.
func TestLive_OpenFGAChecker_RestoreDoesNotResurrectAuthorization(t *testing.T) {
	checker, tessera, ctx := liveOpenFGASetup(t)
	ref := liveAgentRef(t)

	if err := checker.WriteGrants(ctx, ref, []Grant{GrantForTool("invoice.read")}); err != nil {
		t.Fatalf("WriteGrants: %v", err)
	}
	if _, err := checker.Kill(ctx, ref, "INC-live", "bogdan"); err != nil {
		t.Fatalf("Kill: %v", err)
	}
	if err := checker.Restore(ctx, ref); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	// The old answer, straight from Tessera's declared grant list.
	declared, err := tessera.Check(ctx, ref, GrantForTool("invoice.read"))
	if err != nil {
		t.Fatalf("TesseraHTTPClient.Check: %v", err)
	}

	// The new answer, from the authorization store itself.
	live, err := checker.Check(ctx, ref, GrantForTool("invoice.read"))
	if err != nil {
		t.Fatalf("OpenFGAChecker.Check: %v", err)
	}
	if live {
		t.Fatal("OpenFGAChecker.Check = true after Kill then Restore, but the kill deleted the tuples and nothing has written them back")
	}
	if !declared {
		t.Skip("TesseraHTTPClient.Check also returned false, so this deployment's Tessera no longer keeps declared grants across a kill, the divergence this test documents does not exist here")
	}
	t.Logf("confirmed the divergence: Tessera's declared grant list says allowed=%v, live OpenFGA says allowed=%v", declared, live)
}

// TestLive_OpenFGAChecker_KillDeniesImmediately covers the ordinary
// containment path through the same client, so the fix above is not
// mistaken for having weakened the thing that already worked.
func TestLive_OpenFGAChecker_KillDeniesImmediately(t *testing.T) {
	checker, _, ctx := liveOpenFGASetup(t)
	ref := liveAgentRef(t)

	if err := checker.WriteGrants(ctx, ref, []Grant{GrantForTool("invoice.read")}); err != nil {
		t.Fatalf("WriteGrants: %v", err)
	}
	allowed, err := checker.Check(ctx, ref, GrantForTool("invoice.read"))
	if err != nil || !allowed {
		t.Fatalf("Check before kill = %v, %v, want true", allowed, err)
	}
	if _, err := checker.Kill(ctx, ref, "INC-live-kill", "bogdan"); err != nil {
		t.Fatalf("Kill: %v", err)
	}
	allowed, err = checker.Check(ctx, ref, GrantForTool("invoice.read"))
	if err != nil {
		t.Fatalf("Check after kill: %v", err)
	}
	if allowed {
		t.Fatal("Check = true after a kill deleted the agent's tuples")
	}
}
