package audit

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/lib/pq"
)

// TestPostgresSink_Live drives a real Postgres instance end to end:
// schema creation on first connect, insert, and both read shapes.
// Opt-in via NIA_AUDIT_TEST_DATABASE_URL (a standard postgres:// DSN),
// skipped by default, same pattern as
// internal/policy/tessera_client_live_test.go uses for a real Tessera
// process. deployments/docker-compose.yml's postgres service, once up,
// is reachable from the host at
// postgres://nia:nia@localhost:5433/nia?sslmode=disable.
func TestPostgresSink_Live(t *testing.T) {
	dsn := os.Getenv("NIA_AUDIT_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NIA_AUDIT_TEST_DATABASE_URL not set, skipping live Postgres test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	sink, err := NewPostgresSink(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPostgresSink: %v", err)
	}
	t.Cleanup(func() { _ = sink.Close() })

	// A ref unique to this run, so repeated runs against the same
	// long-lived database don't see each other's leftover rows and
	// don't need any cleanup step of their own.
	agentRef := "agent:live-test-" + time.Now().Format("20060102T150405.000000000")

	events := []Event{
		{Action: "agent.registered", AgentRef: agentRef, Operator: "bogdan", At: time.Now()},
		{Action: "grant.written", AgentRef: agentRef, Operator: "bogdan", Detail: "tool=invoices.read", At: time.Now().Add(time.Second)},
		{Action: "agent.killed", AgentRef: agentRef, Operator: "bogdan", Incident: "INC-LIVE-001", At: time.Now().Add(2 * time.Second)},
	}
	for _, e := range events {
		if err := sink.Append(ctx, e); err != nil {
			t.Fatalf("Append(%s): %v", e.Action, err)
		}
	}

	got, err := sink.ForAgent(ctx, agentRef)
	if err != nil {
		t.Fatalf("ForAgent: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("ForAgent returned %d events, want 3: %v", len(got), got)
	}
	if got[0].Action != "agent.registered" || got[2].Action != "agent.killed" {
		t.Fatalf("ForAgent order wrong: %v", got)
	}
	if got[2].Incident != "INC-LIVE-001" {
		t.Fatalf("Incident = %q, want INC-LIVE-001", got[2].Incident)
	}

	// Recent has to find these same three rows mixed in with whatever
	// else is in the table, proving the ORDER BY ... DESC ... LIMIT
	// then reverse round trip actually preserves oldest-first order and
	// doesn't drop rows at the boundary.
	recent, err := sink.Recent(ctx, 1000)
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	var found []Event
	for _, e := range recent {
		if e.AgentRef == agentRef {
			found = append(found, e)
		}
	}
	if len(found) != 3 {
		t.Fatalf("Recent(1000) contained %d events for %s, want 3: %v", len(found), agentRef, found)
	}
	if found[0].Action != "agent.registered" || found[2].Action != "agent.killed" {
		t.Fatalf("Recent order wrong for this agent's events: %v", found)
	}
}

// TestPostgresSink_ChainLive_VerifyPassesOnAnUntamperedChain and the
// four tests below it drive real SQL, actual UPDATE/DELETE/INSERT
// statements against a real audit_events table, not a simulated
// tamper against an in-memory struct, the strongest form of proof this
// codebase's own verification standard asks for: run it against the
// real thing at least once. Each test writes a small, uniquely-named
// chain of its own so it can find exactly its own rows afterward and
// tamper with only those, leaving whatever else is in a shared,
// long-lived test database alone.
func TestPostgresSink_ChainLive_VerifyPassesOnAnUntamperedChain(t *testing.T) {
	sink, ctx := liveChainSink(t)
	agentRef := liveChainAgentRef(t)
	appendLiveChain(t, ctx, sink, agentRef, 4)

	result, err := Verify(ctx, sink)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !result.OK {
		t.Fatalf("got %+v, want OK for an untampered live chain", result)
	}
}

func TestPostgresSink_ChainLive_DetectsModifiedEvent(t *testing.T) {
	sink, ctx := liveChainSink(t)
	agentRef := liveChainAgentRef(t)
	seqs := appendLiveChain(t, ctx, sink, agentRef, 3)

	if _, err := sink.db.ExecContext(ctx, `UPDATE audit_events SET detail = 'tampered' WHERE id = $1`, seqs[1]); err != nil {
		t.Fatalf("tampering UPDATE: %v", err)
	}

	assertLiveChainBroken(t, ctx, sink, seqs[1])
}

func TestPostgresSink_ChainLive_DetectsDeletedEvent(t *testing.T) {
	sink, ctx := liveChainSink(t)
	agentRef := liveChainAgentRef(t)
	seqs := appendLiveChain(t, ctx, sink, agentRef, 4)

	if _, err := sink.db.ExecContext(ctx, `DELETE FROM audit_events WHERE id = $1`, seqs[1]); err != nil {
		t.Fatalf("tampering DELETE: %v", err)
	}

	// The break surfaces on the event that used to follow the deleted
	// one, its prev_hash no longer matches anything present.
	assertLiveChainBroken(t, ctx, sink, seqs[2])
}

// TestPostgresSink_ChainLive_DetectsInsertedEvent simulates a forged
// event replacing a real one under the same row id. A plain INSERT
// can't land a new row strictly between two existing, contiguous
// BIGSERIAL ids (there is no integer between N and N+1), the same
// constraint a real attacker with ordinary INSERT access to this table
// would run into; the realistic move is to delete the row they want to
// replace and insert a forged one back under its now-free id, which is
// exactly what this does.
func TestPostgresSink_ChainLive_DetectsInsertedEvent(t *testing.T) {
	sink, ctx := liveChainSink(t)
	agentRef := liveChainAgentRef(t)
	seqs := appendLiveChain(t, ctx, sink, agentRef, 3)

	var predecessorHash string
	if err := sink.db.QueryRowContext(ctx, `SELECT hash FROM audit_events WHERE id = $1`, seqs[0]).Scan(&predecessorHash); err != nil {
		t.Fatalf("reading predecessor hash: %v", err)
	}

	if _, err := sink.db.ExecContext(ctx, `DELETE FROM audit_events WHERE id = $1`, seqs[1]); err != nil {
		t.Fatalf("deleting to free the id: %v", err)
	}

	forged := Event{Action: "grant.written", AgentRef: agentRef, Detail: "forged", At: time.Now()}
	forgedHash := chainHash(forged, predecessorHash)
	// A forged row with a self-consistent hash (computed with the real,
	// public algorithm), reinserted under the id it just freed, the way
	// an attacker with ordinary DELETE+INSERT access to this table
	// could, without touching anything that comes after it.
	if _, err := sink.db.ExecContext(ctx,
		`INSERT INTO audit_events (id, action, agent_ref, operator, incident, detail, at, hash, prev_hash) VALUES ($1,$2,$3,'','',$4,$5,$6,$7)`,
		seqs[1], forged.Action, forged.AgentRef, forged.Detail, forged.At, forgedHash, predecessorHash,
	); err != nil {
		t.Fatalf("tampering INSERT: %v", err)
	}

	// The forged row's own hash checks out (it was computed correctly),
	// the break is downstream: the real next event's prev_hash still
	// points at the original (now-replaced) event's hash, not the
	// forged one.
	assertLiveChainBroken(t, ctx, sink, seqs[2])
}

func TestPostgresSink_ChainLive_DetectsReorderedEvents(t *testing.T) {
	sink, ctx := liveChainSink(t)
	agentRef := liveChainAgentRef(t)
	seqs := appendLiveChain(t, ctx, sink, agentRef, 3)

	// Swap the two middle events' content (detail and at, the two
	// fields appendLiveChain actually varies per event) in place via
	// SQL, leaving their id, hash, and prev_hash columns exactly as
	// originally written, the shape a reordering that doesn't also
	// rewrite the hash chain takes: each row's recorded hash no longer
	// matches the data now sitting at that id.
	tx, err := sink.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	var detail0, detail1 string
	var at0, at1 time.Time
	if err := tx.QueryRowContext(ctx, `SELECT detail, at FROM audit_events WHERE id = $1`, seqs[0]).Scan(&detail0, &at0); err != nil {
		t.Fatalf("reading row 0: %v", err)
	}
	if err := tx.QueryRowContext(ctx, `SELECT detail, at FROM audit_events WHERE id = $1`, seqs[1]).Scan(&detail1, &at1); err != nil {
		t.Fatalf("reading row 1: %v", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE audit_events SET detail = $1, at = $2 WHERE id = $3`, detail1, at1, seqs[0]); err != nil {
		t.Fatalf("swapping row 0: %v", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE audit_events SET detail = $1, at = $2 WHERE id = $3`, detail0, at0, seqs[1]); err != nil {
		t.Fatalf("swapping row 1: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	assertLiveChainBroken(t, ctx, sink, seqs[0], seqs[1])
}

// liveChainSink is TestPostgresSink_Live's own setup, factored out so
// every chain tampering test below gets the same opt-in skip and the
// same real connection without repeating it five times.
func liveChainSink(t *testing.T) (*PostgresSink, context.Context) {
	t.Helper()
	dsn := os.Getenv("NIA_AUDIT_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NIA_AUDIT_TEST_DATABASE_URL not set, skipping live Postgres test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	sink, err := NewPostgresSink(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPostgresSink: %v", err)
	}
	t.Cleanup(func() { _ = sink.Close() })
	return sink, ctx
}

func liveChainAgentRef(t *testing.T) string {
	t.Helper()
	return "agent:chain-live-" + time.Now().Format("20060102T150405.000000000")
}

// appendLiveChain writes n real events for agentRef and returns their
// row ids in order, the handle every tampering test needs to target
// exactly its own rows with raw SQL afterward.
func appendLiveChain(t *testing.T, ctx context.Context, sink *PostgresSink, agentRef string, n int) []int64 {
	t.Helper()
	// Every one of these tests deliberately corrupts real rows, and
	// this database is shared and long-lived, the same one
	// TestPostgresSink_Live itself points at. Leaving tampered rows
	// behind would make a later run's own "untampered chain" assertion
	// fail against damage a previous run did, not anything the later
	// run itself caused, so each test cleans up exactly its own rows
	// (matched by this run's unique agentRef, including any forged row
	// a test inserted under the same ref) once it finishes, tampered or
	// not.
	//
	// Deleting the rows is no longer enough on its own. Verify now also
	// compares the last event's hash against audit_chain_state.last_hash
	// (see Chain.Tip), so a test that removes its own rows and leaves
	// the tip pointing at one of them has done exactly what the
	// truncation check is designed to catch, and every later test's
	// "untampered chain" assertion would fail against that leftover
	// rather than against anything it did itself. Capture the tip
	// before this test writes anything and put it back afterward, so
	// cleanup undoes the whole of this test's effect on the chain, not
	// just the visible half.
	var tipBefore string
	if err := sink.db.QueryRowContext(ctx, `SELECT last_hash FROM audit_chain_state WHERE id = TRUE`).Scan(&tipBefore); err != nil {
		t.Fatalf("reading chain tip before the test: %v", err)
	}
	t.Cleanup(func() {
		if _, err := sink.db.ExecContext(context.Background(), `DELETE FROM audit_events WHERE agent_ref = $1`, agentRef); err != nil {
			t.Logf("cleanup: deleting rows for %s: %v", agentRef, err)
		}
		if _, err := sink.db.ExecContext(context.Background(), `UPDATE audit_chain_state SET last_hash = $1 WHERE id = TRUE`, tipBefore); err != nil {
			t.Logf("cleanup: restoring chain tip: %v", err)
		}
	})
	for i := 0; i < n; i++ {
		// Detail carries the index so events in the same chain are never
		// content-identical, a test that swaps or modifies one event
		// needs the change to actually alter the canonicalized bytes,
		// not silently swap two identical values.
		evt := Event{Action: "gateway.allowed", AgentRef: agentRef, Operator: agentRef, Detail: fmt.Sprintf("tool=invoice.read seq=%d", i), At: time.Now().Add(time.Duration(i) * time.Millisecond)}
		if err := sink.Append(ctx, evt); err != nil {
			t.Fatalf("Append #%d: %v", i, err)
		}
	}
	rows, err := sink.db.QueryContext(ctx, `SELECT id FROM audit_events WHERE agent_ref = $1 ORDER BY id ASC`, agentRef)
	if err != nil {
		t.Fatalf("querying ids: %v", err)
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("scanning id: %v", err)
		}
		ids = append(ids, id)
	}
	if len(ids) != n {
		t.Fatalf("wrote %d events but found %d rows for %s", n, len(ids), agentRef)
	}
	return ids
}

// assertLiveChainBroken runs Verify against the real, now-tampered
// table and fails the test unless every one of wantSeqs shows up
// somewhere in the reported breaks. It deliberately checks the whole
// table's chain, not just this test's own rows: a tamper anywhere must
// not be maskable by scoping verification to a subset of the trail.
func assertLiveChainBroken(t *testing.T, ctx context.Context, sink *PostgresSink, wantSeqs ...int64) {
	t.Helper()
	result, err := Verify(ctx, sink)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.OK {
		t.Fatal("got OK=true, want the live tamper to be caught")
	}
	seen := map[int64]bool{}
	for _, b := range result.Breaks {
		seen[b.Seq] = true
	}
	for _, want := range wantSeqs {
		if !seen[want] {
			t.Fatalf("got breaks %v, want Seq=%d flagged", result.Breaks, want)
		}
	}
}

// TestPostgresSink_ChainLive_DetectsTruncatedChain is the tampering
// shape none of the tests above can catch by walking events alone:
// delete the newest rows and everything that remains still links up
// perfectly, because the break is at an end that no longer exists. Only
// audit_chain_state.last_hash, a different table the attacker also has
// to remember to rewrite, still knows the chain went further. See
// Chain.Tip.
func TestPostgresSink_ChainLive_DetectsTruncatedChain(t *testing.T) {
	sink, ctx := liveChainSink(t)
	agentRef := liveChainAgentRef(t)
	seqs := appendLiveChain(t, ctx, sink, agentRef, 4)

	if _, err := sink.db.ExecContext(ctx, `DELETE FROM audit_events WHERE id = ANY($1)`, pq.Array([]int64{seqs[2], seqs[3]})); err != nil {
		t.Fatalf("tampering DELETE: %v", err)
	}

	result, err := Verify(ctx, sink)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.OK {
		t.Fatalf("got %+v, want OK false: the two surviving events are self-consistent but the recorded tip proves two more existed", result)
	}
	if len(result.Breaks) != 1 || result.Breaks[0].Seq != seqs[1] {
		t.Fatalf("Breaks = %+v, want one break naming the last surviving event (seq %d)", result.Breaks, seqs[1])
	}
}

// TestPostgresSink_ChainLive_DetectsClearedHashColumn covers the other
// way to make a row escape verification: leave it in place but blank
// its hash so it looks like a row written before chaining existed.
func TestPostgresSink_ChainLive_DetectsClearedHashColumn(t *testing.T) {
	sink, ctx := liveChainSink(t)
	agentRef := liveChainAgentRef(t)
	seqs := appendLiveChain(t, ctx, sink, agentRef, 3)

	if _, err := sink.db.ExecContext(ctx,
		`UPDATE audit_events SET detail = 'tampered', hash = '', prev_hash = '' WHERE id = $1`, seqs[1],
	); err != nil {
		t.Fatalf("tampering UPDATE: %v", err)
	}

	result, err := Verify(ctx, sink)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.OK {
		t.Fatalf("got %+v, want OK false: a blanked hash on a row that follows a hashed row is tampering, not a legacy row", result)
	}
	var sawCleared bool
	for _, b := range result.Breaks {
		if b.Seq == seqs[1] {
			sawCleared = true
		}
	}
	if !sawCleared {
		t.Fatalf("Breaks = %+v, want one naming the blanked row (seq %d)", result.Breaks, seqs[1])
	}
}

// TestPostgresSink_ChainLive_VerifyDuringConcurrentAppendsIsNeverAFalseBreak
// guards the tip check against the failure mode it could plausibly
// introduce. The events and the tip are in two different tables, so a
// Chain that read them under two separate snapshots would see a tip
// newer than its newest event whenever an append landed in between, and
// report a truncation on a perfectly healthy trail. cmd/api serves
// GET /audit/verify while cmd/gateway is still appending, so that is
// the ordinary case, not a rare one, and a verifier that cries tamper
// under load is worse than no verifier.
func TestPostgresSink_ChainLive_VerifyDuringConcurrentAppendsIsNeverAFalseBreak(t *testing.T) {
	sink, ctx := liveChainSink(t)
	agentRef := liveChainAgentRef(t)
	appendLiveChain(t, ctx, sink, agentRef, 2)

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			evt := Event{
				Action:   "gateway.allowed",
				AgentRef: agentRef,
				Operator: agentRef,
				Detail:   fmt.Sprintf("concurrent seq=%d", i),
				At:       time.Now(),
			}
			if err := sink.Append(context.Background(), evt); err != nil {
				t.Errorf("concurrent Append #%d: %v", i, err)
				return
			}
		}
	}()

	for i := 0; i < 25; i++ {
		result, err := Verify(ctx, sink)
		if err != nil {
			close(stop)
			<-done
			t.Fatalf("Verify #%d: %v", i, err)
		}
		if !result.OK {
			close(stop)
			<-done
			t.Fatalf("Verify #%d reported breaks on a healthy chain while appends were in flight: %+v", i, result.Breaks)
		}
	}
	close(stop)
	<-done
}
