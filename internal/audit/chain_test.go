package audit

import (
	"context"
	"testing"
	"time"
)

func appendN(t *testing.T, sink *InMemorySink, n int, agentRef string) {
	t.Helper()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < n; i++ {
		err := sink.Append(context.Background(), Event{
			Action:   "gateway.allowed",
			AgentRef: agentRef,
			Operator: agentRef,
			Detail:   "tool=invoice.read",
			At:       base.Add(time.Duration(i) * time.Second),
		})
		if err != nil {
			t.Fatalf("Append #%d: %v", i, err)
		}
	}
}

func TestVerify_EmptyChain_OK(t *testing.T) {
	sink := NewInMemorySink(100)
	result, err := Verify(context.Background(), sink)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !result.OK || result.Checked != 0 || len(result.Breaks) != 0 {
		t.Fatalf("got %+v, want an empty chain to verify clean", result)
	}
}

func TestVerify_ValidChain_OK(t *testing.T) {
	sink := NewInMemorySink(100)
	appendN(t, sink, 5, "agent:billing")

	result, err := Verify(context.Background(), sink)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !result.OK {
		t.Fatalf("got %+v, want OK for an untampered chain", result)
	}
	if result.Checked != 5 {
		t.Fatalf("Checked = %d, want 5", result.Checked)
	}
	if result.Skipped != 0 {
		t.Fatalf("Skipped = %d, want 0", result.Skipped)
	}
	if len(result.Breaks) != 0 {
		t.Fatalf("Breaks = %v, want none", result.Breaks)
	}
}

// TestVerify_FirstEventMustChainFromGenesis is the defined behavior for
// the first event in a chain: its own prev_hash must equal GenesisHash,
// not an empty string, not arbitrary content. Tampering the very first
// event's prev_hash away from genesis must be caught the same as any
// other broken link.
func TestVerify_FirstEventMustChainFromGenesis(t *testing.T) {
	sink := NewInMemorySink(100)
	appendN(t, sink, 3, "agent:billing")

	sink.mu.Lock()
	sink.chain[0].PrevHash = "not-the-genesis-value"
	sink.mu.Unlock()

	result, err := Verify(context.Background(), sink)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.OK {
		t.Fatal("got OK=true, want the tampered genesis link to be caught")
	}
	found := false
	for _, b := range result.Breaks {
		if b.Seq == 1 {
			found = true
		}
	}
	if !found {
		t.Fatalf("got breaks %v, want one naming Seq=1 (the first event)", result.Breaks)
	}
}

// TestVerify_DetectsModifiedEvent covers the first named tampering
// case: an event's data was changed after it was written, without
// recomputing its own hash to match. This is the most direct kind of
// tamper, editing history in place.
func TestVerify_DetectsModifiedEvent(t *testing.T) {
	sink := NewInMemorySink(100)
	appendN(t, sink, 4, "agent:billing")

	sink.mu.Lock()
	sink.chain[2].Detail = "tool=invoice.delete" // changed after the fact, hash left as-is
	sink.mu.Unlock()

	result, err := Verify(context.Background(), sink)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.OK {
		t.Fatal("got OK=true, want a modified event to be caught")
	}
	found := false
	for _, b := range result.Breaks {
		if b.Seq == 3 { // 1-indexed Seq, the third appended event
			found = true
		}
	}
	if !found {
		t.Fatalf("got breaks %v, want one naming Seq=3 (the modified event)", result.Breaks)
	}
}

// TestVerify_DetectsDeletedEvent covers removing a row outright: the
// event after the deleted one still carries the prev_hash it was
// actually written with, which now points at a hash nothing in the
// remaining chain has, a gap Verify has to notice without ever being
// told an event went missing.
func TestVerify_DetectsDeletedEvent(t *testing.T) {
	sink := NewInMemorySink(100)
	appendN(t, sink, 5, "agent:billing")

	sink.mu.Lock()
	// Remove the third event (Seq=3), simulating a DELETE FROM
	// audit_events WHERE id = 3 against the real table.
	sink.chain = append(sink.chain[:2], sink.chain[3:]...)
	sink.mu.Unlock()

	result, err := Verify(context.Background(), sink)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.OK {
		t.Fatal("got OK=true, want a deleted event to be caught")
	}
	if result.Checked != 4 {
		t.Fatalf("Checked = %d, want 4 (one of the original 5 was deleted)", result.Checked)
	}
	// The break shows up on the event that used to follow the deleted
	// one, Seq=4, its prev_hash no longer matches anything present.
	found := false
	for _, b := range result.Breaks {
		if b.Seq == 4 {
			found = true
		}
	}
	if !found {
		t.Fatalf("got breaks %v, want one naming Seq=4 (the event right after the deletion)", result.Breaks)
	}
}

// TestVerify_DetectsInsertedEvent covers a forged row spliced into the
// middle of the chain. The forger can compute a self-consistent hash
// for their own fabricated event (the algorithm is public), but unless
// they also rewrite every event after it, the very next real event's
// stored prev_hash still points at the real predecessor's hash, not
// the forged one, and that mismatch is what gets caught, exactly the
// "tamper evidence, not tamper proof" boundary this package's own doc
// comment names: forging one entry without rewriting the entire
// downstream suffix is detectable, forging the whole suffix too is a
// different, much larger act this package doesn't claim to catch.
func TestVerify_DetectsInsertedEvent(t *testing.T) {
	sink := NewInMemorySink(100)
	appendN(t, sink, 4, "agent:billing")

	sink.mu.Lock()
	realPredecessorHash := sink.chain[1].Hash
	forged := Event{Action: "grant.written", AgentRef: "agent:billing", Detail: "tool=admin.delete_all", At: time.Now()}
	forgedHash := chainHash(forged, realPredecessorHash) // self-consistent, computed with the real algorithm
	forgedEntry := ChainedEvent{Event: forged, Seq: 100, Hash: forgedHash, PrevHash: realPredecessorHash}
	// Splice it in after index 1, before the original event at index 2,
	// the way an attacker with raw INSERT access to audit_events could,
	// without renumbering or rewriting anything that follows.
	tail := append([]ChainedEvent{forgedEntry}, sink.chain[2:]...)
	sink.chain = append(sink.chain[:2], tail...)
	sink.mu.Unlock()

	result, err := Verify(context.Background(), sink)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.OK {
		t.Fatal("got OK=true, want an inserted event to be caught")
	}
	// The forged entry's own hash checks out fine (self-consistent by
	// construction), the break is downstream: the original next event's
	// prev_hash no longer matches the forged entry's hash.
	found := false
	for _, b := range result.Breaks {
		if b.Seq == 3 { // the original third event, now displaced one position later
			found = true
		}
	}
	if !found {
		t.Fatalf("got breaks %v, want one naming Seq=3 (the real event after the forged insertion)", result.Breaks)
	}
}

// TestVerify_DetectsReorderedEvents covers swapping two events' content
// while leaving their storage-layer identity (Seq, Hash, PrevHash)
// alone, the shape a reordering attack that doesn't also rewrite the
// hash chain takes: each event's own recorded hash no longer matches
// the data now sitting at that position.
func TestVerify_DetectsReorderedEvents(t *testing.T) {
	sink := NewInMemorySink(100)
	appendN(t, sink, 4, "agent:billing")

	sink.mu.Lock()
	sink.chain[1].Event, sink.chain[2].Event = sink.chain[2].Event, sink.chain[1].Event
	sink.mu.Unlock()

	result, err := Verify(context.Background(), sink)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.OK {
		t.Fatal("got OK=true, want reordered events to be caught")
	}
	seen := map[int64]bool{}
	for _, b := range result.Breaks {
		seen[b.Seq] = true
	}
	if !seen[2] || !seen[3] {
		t.Fatalf("got breaks %v, want both Seq=2 and Seq=3 flagged, their content no longer matches their own recorded hash", result.Breaks)
	}
}

// fakeChainedStore lets a test hand Verify an exact Chain by
// construction, for the cases that are about Verify's own logic (the
// genesis rule, skipping pre-chain rows) rather than about a
// particular Sink's tampering behavior.
type fakeChainedStore struct {
	chain Chain
}

func (f fakeChainedStore) Chain(_ context.Context) (Chain, error) {
	return f.chain, nil
}

// TestVerify_SkipsPreChainEventsWithEmptyHash covers a table that had
// rows in it before hash chaining was enabled (see PostgresSink's
// ALTER TABLE migration): those rows have Hash == "" forever, they
// never had a hash computed for them, and Verify must not treat that
// as tampering, only the genuinely chained rows that follow are
// checked, and the first genuinely chained row is correctly expected
// to chain from GenesisHash, exactly as PostgresSink's chain state
// starts fresh regardless of what pre-existing unhashed rows are still
// sitting in the table.
func TestVerify_SkipsPreChainEventsWithEmptyHash(t *testing.T) {
	legacy := ChainedEvent{Event: Event{Action: "legacy.event", At: time.Now()}, Seq: 1}
	first := Event{Action: "agent.registered", AgentRef: "agent:billing", At: time.Now()}
	firstHash := chainHash(first, GenesisHash)
	second := Event{Action: "grant.written", AgentRef: "agent:billing", At: time.Now()}
	secondHash := chainHash(second, firstHash)

	store := fakeChainedStore{chain: Chain{
		StartsAtGenesis: true,
		Events: []ChainedEvent{
			legacy, // Hash == "", predates the migration
			{Event: first, Seq: 2, Hash: firstHash, PrevHash: GenesisHash},
			{Event: second, Seq: 3, Hash: secondHash, PrevHash: firstHash},
		},
	}}

	result, err := Verify(context.Background(), store)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !result.OK {
		t.Fatalf("got %+v, want OK: the legacy row should be skipped, not flagged, and the real chain after it is intact", result)
	}
	if result.Skipped != 1 {
		t.Fatalf("Skipped = %d, want 1", result.Skipped)
	}
	if result.Checked != 2 {
		t.Fatalf("Checked = %d, want 2", result.Checked)
	}
}

// TestVerify_StartsAtGenesisFalse_SkipsGenesisCheckOnFirstEvent covers
// InMemorySink after it has evicted events past capacity: the window
// Verify sees is real and internally consistent, it just doesn't start
// at the true beginning of the chain, and that must not be flagged as
// a broken genesis link.
func TestVerify_StartsAtGenesisFalse_SkipsGenesisCheckOnFirstEvent(t *testing.T) {
	sink := NewInMemorySink(3)
	appendN(t, sink, 5, "agent:billing") // 2 evicted past the cap of 3

	chain, err := sink.Chain(context.Background())
	if err != nil {
		t.Fatalf("Chain: %v", err)
	}
	if chain.StartsAtGenesis {
		t.Fatal("StartsAtGenesis = true, want false after eviction")
	}
	if chain.Events[0].PrevHash == GenesisHash {
		t.Fatal("test setup broken: the retained window's first event should NOT chain from genesis after eviction")
	}

	result, err := Verify(context.Background(), sink)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !result.OK {
		t.Fatalf("got %+v, want OK: eviction is not tampering", result)
	}
	if result.Checked != 3 {
		t.Fatalf("Checked = %d, want 3 (the retained window)", result.Checked)
	}
}

func TestChainHash_SameEventDifferentPrevHash_DifferentHash(t *testing.T) {
	evt := Event{Action: "gateway.allowed", AgentRef: "agent:billing", At: time.Now()}
	h1 := chainHash(evt, GenesisHash)
	h2 := chainHash(evt, "some-other-prev-hash")
	if h1 == h2 {
		t.Fatal("chainHash produced the same hash for two different prev_hash values, the chain would not actually link anything")
	}
}

func TestChainHash_DifferentEventSamePrevHash_DifferentHash(t *testing.T) {
	h1 := chainHash(Event{Action: "gateway.allowed", AgentRef: "agent:billing", At: time.Unix(0, 0)}, GenesisHash)
	h2 := chainHash(Event{Action: "gateway.denied", AgentRef: "agent:billing", At: time.Unix(0, 0)}, GenesisHash)
	if h1 == h2 {
		t.Fatal("chainHash produced the same hash for two different events, a modification wouldn't be detectable")
	}
}

func TestChainHash_Deterministic(t *testing.T) {
	evt := Event{Action: "gateway.allowed", AgentRef: "agent:billing", Operator: "agent:billing", Incident: "INC-1", Detail: "tool=x", At: time.Unix(1234567890, 0)}
	if chainHash(evt, GenesisHash) != chainHash(evt, GenesisHash) {
		t.Fatal("chainHash is not deterministic for identical inputs")
	}
}

// TestChainHash_FieldBoundariesDontCollide guards against a
// concatenation bug where two different splits of the same total
// string produce the same canonical bytes, e.g. Action="a"
// AgentRef="bc" colliding with Action="ab" AgentRef="c".
func TestChainHash_FieldBoundariesDontCollide(t *testing.T) {
	at := time.Unix(0, 0)
	h1 := chainHash(Event{Action: "a", AgentRef: "bc", At: at}, GenesisHash)
	h2 := chainHash(Event{Action: "ab", AgentRef: "c", At: at}, GenesisHash)
	if h1 == h2 {
		t.Fatal("chainHash collided across a field boundary, canonicalize needs a separator")
	}
}
