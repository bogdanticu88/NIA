package policy

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// tesseraRepoPathEnv points this test at a checked out Tessera repo with
// src/Tessera.Service already built (dotnet build src/Tessera.Service).
// NIA does not vendor Tessera's source, they are separate repos, so this
// is an opt in cross service check for local development, not something
// `go test ./...` can run unattended in CI without that repo present.
// Every other test in this package runs against httptest and needs
// neither dotnet nor a second repo, this is the one exception, deliberate
// for the same reason Tessera's own ServiceHarness has a live HTTP test
// alongside its in-process ones: unit tests against a fake server confirm
// this client's own logic, they cannot confirm the wire format this
// client speaks is the wire format Tessera's real ASP.NET pipeline,
// JSON binding, and Hs256JwtValidator actually accept. Only spawning the
// real thing catches that class of mismatch, one already turned up once
// on the Tessera side during this work (enum fields serializing as bare
// integers instead of the snake_case strings this client expects).
const tesseraRepoPathEnv = "NIA_TESSERA_REPO_PATH"

func TestLive_TesseraHTTPClient_AgainstRealTesseraService(t *testing.T) {
	repoRoot := os.Getenv(tesseraRepoPathEnv)
	if repoRoot == "" {
		t.Skipf("skipping live cross-service test: set %s to a checked out tessera repo to run it, for example NIA_TESSERA_REPO_PATH=/home/claude/tessera", tesseraRepoPathEnv)
	}

	dllPath := filepath.Join(repoRoot, "src", "Tessera.Service", "bin", "Debug", "net8.0", "Tessera.Service.dll")
	if _, err := os.Stat(dllPath); err != nil {
		t.Skipf("skipping live cross-service test: %s not built yet, run `dotnet build src/Tessera.Service` in %s first (%v)", dllPath, repoRoot, err)
	}

	port := freeTCPPort(t)
	signingKey := make([]byte, 32)
	if _, err := rand.Read(signingKey); err != nil {
		t.Fatalf("generating a signing key: %v", err)
	}

	cmd := exec.Command("dotnet", dllPath)
	cmd.Env = append(os.Environ(),
		"ASPNETCORE_URLS=http://127.0.0.1:"+strconv.Itoa(port),
		"TESSERA_JWT_SIGNING_KEY="+base64.StdEncoding.EncodeToString(signingKey),
		"TESSERA_JWT_ISSUER=nia-live-test-issuer",
		"TESSERA_JWT_AUDIENCE=nia-live-test-audience",
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting Tessera.Service: %v", err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
		if t.Failed() && stderr.Len() > 0 {
			t.Logf("Tessera.Service stderr:\n%s", stderr.String())
		}
	})

	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	waitForHealthy(t, baseURL, 15*time.Second)

	client, err := NewTesseraHTTPClient(baseURL, nil, signingKey, "nia-live-test-issuer", "nia-live-test-audience", "nia-system")
	if err != nil {
		t.Fatalf("NewTesseraHTTPClient: %v", err)
	}

	ctx := context.Background()
	const agentRef = "live-smoke-agent"

	// A never-onboarded agent looks empty and alive, not an error, same
	// as InMemoryClient.
	if killed, err := client.IsKilled(ctx, agentRef); err != nil || killed {
		t.Fatalf("IsKilled on a fresh agent: killed=%v err=%v", killed, err)
	}
	if grants, err := client.ListGrants(ctx, agentRef); err != nil || len(grants) != 0 {
		t.Fatalf("ListGrants on a fresh agent: grants=%v err=%v", grants, err)
	}

	// WriteGrants onboards it. One api_group grant and one tool grant, to
	// exercise the tool/data wire encoding against the real service, not
	// just against this package's own decoder.
	if err := client.WriteGrants(ctx, agentRef, []Grant{GrantForAPIGroup("orders"), GrantForTool("search")}); err != nil {
		t.Fatalf("WriteGrants: %v", err)
	}

	allowed, err := client.Check(ctx, agentRef, GrantForAPIGroup("orders"))
	if err != nil || !allowed {
		t.Fatalf("Check(orders) after WriteGrants: allowed=%v err=%v", allowed, err)
	}
	allowedTool, err := client.Check(ctx, agentRef, GrantForTool("search"))
	if err != nil || !allowedTool {
		t.Fatalf("Check(tool search) after WriteGrants: allowed=%v err=%v", allowedTool, err)
	}
	grants, err := client.ListGrants(ctx, agentRef)
	if err != nil || len(grants) != 2 {
		t.Fatalf("ListGrants after WriteGrants: grants=%v err=%v", grants, err)
	}

	// DeleteGrants removes exactly the one grant asked for.
	if err := client.DeleteGrants(ctx, agentRef, []Grant{GrantForTool("search")}); err != nil {
		t.Fatalf("DeleteGrants: %v", err)
	}
	grants, err = client.ListGrants(ctx, agentRef)
	if err != nil || len(grants) != 1 || grants[0] != GrantForAPIGroup("orders") {
		t.Fatalf("ListGrants after DeleteGrants: expected only the orders grant left, got grants=%v err=%v", grants, err)
	}

	// Kill, with real per-operator attribution, against the real
	// Hs256JwtValidator and the real audit sink.
	killResult, err := client.Kill(ctx, agentRef, "INC-LIVE-1", "alice")
	if err != nil {
		t.Fatalf("Kill: %v", err)
	}
	if killResult.TuplesDeleted != 1 {
		t.Fatalf("expected 1 tuple deleted by kill (the orders grant), got %d", killResult.TuplesDeleted)
	}
	if allowed, err := client.Check(ctx, agentRef, GrantForAPIGroup("orders")); err != nil || allowed {
		t.Fatalf("Check after kill: allowed=%v err=%v, a killed agent must never be allowed", allowed, err)
	}
	if killed, err := client.IsKilled(ctx, agentRef); err != nil || !killed {
		t.Fatalf("IsKilled after kill: killed=%v err=%v", killed, err)
	}

	// A write against a killed agent is an error, not a silent no-op,
	// same invariant InMemoryClient enforces.
	if err := client.WriteGrants(ctx, agentRef, []Grant{GrantForAPIGroup("billing")}); err == nil {
		t.Fatal("expected WriteGrants against a killed agent to fail")
	}

	// Restore clears the kill sentinel. It does not touch the declared
	// grant list in Tessera's registry either way, kill never cleared it
	// in the first place, that's a real, verified difference from
	// InMemoryClient (whose Kill wipes the grants map entry outright).
	// ListGrants right after restore reports the previously declared
	// grants, "orders" included, even though the live OpenFGA tuple for
	// it is still gone, kill deleted that and restore doesn't rewrite it.
	if err := client.Restore(ctx, agentRef); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if killed, err := client.IsKilled(ctx, agentRef); err != nil || killed {
		t.Fatalf("IsKilled after restore: killed=%v err=%v", killed, err)
	}
	if grants, err := client.ListGrants(ctx, agentRef); err != nil || len(grants) != 1 || grants[0] != GrantForAPIGroup("orders") {
		t.Fatalf("ListGrants right after restore: expected the previously declared 'orders' grant still listed, got grants=%v err=%v", grants, err)
	}

	// The caller re-declares intent after restore, same as the doc
	// comment on Client.Restore says it must, WriteGrants(agentRef,
	// [orders]) here asks for exactly what's already declared. The real
	// assertion is not Check, Check and ListGrants both read the same
	// declared-state GET response this client can't tell apart from live
	// OpenFGA truth over this HTTP surface, so a stale declared list
	// would make Check pass right after restore even with nothing
	// actually authorized, which is exactly the bug this fixed. Kill
	// again instead and look at TuplesDeleted, that number reflects
	// Tessera's live OpenFGA state directly: 1 only if the write
	// actually reconciled the tuple back in, 0 if it didn't.
	if err := client.WriteGrants(ctx, agentRef, []Grant{GrantForAPIGroup("orders")}); err != nil {
		t.Fatalf("WriteGrants after restore: %v", err)
	}
	secondKill, err := client.Kill(ctx, agentRef, "INC-LIVE-2", "alice")
	if err != nil {
		t.Fatalf("second Kill: %v", err)
	}
	if secondKill.TuplesDeleted != 1 {
		t.Fatalf("expected the post-restore WriteGrants to have actually re-applied the orders tuple to OpenFGA (1 tuple for this kill to delete), got %d, WriteGrants may have skipped the onboard call it needed to make", secondKill.TuplesDeleted)
	}
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("finding a free port: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func waitForHealthy(t *testing.T, baseURL string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := http.Get(baseURL + "/healthz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
			lastErr = fmt.Errorf("unexpected status %d from /healthz", resp.StatusCode)
		} else {
			lastErr = err
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("service did not become healthy within %s, last error: %v", timeout, lastErr)
}
