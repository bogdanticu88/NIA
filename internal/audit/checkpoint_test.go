package audit

import (
	"context"
	"errors"
	"testing"
	"time"
)

func testCheckpointer(t *testing.T) *Checkpointer {
	t.Helper()
	c, err := NewCheckpointer([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("NewCheckpointer: %v", err)
	}
	return c
}

func TestNewCheckpointer_RejectsAShortKey(t *testing.T) {
	if _, err := NewCheckpointer([]byte("too-short")); err == nil {
		t.Fatal("a short key was accepted, that is the kind of thing that looks configured and is not")
	}
}

func TestCheckpointer_NilIsNotConfigured(t *testing.T) {
	var c *Checkpointer
	if c.Configured() {
		t.Fatal("a nil Checkpointer reports configured")
	}
	if _, _, err := c.Create(context.Background(), NewInMemorySink(10)); !errors.Is(err, ErrNoCheckpointKey) {
		t.Fatalf("Create on a nil Checkpointer = %v, want ErrNoCheckpointKey", err)
	}
	if err := c.VerifySignature(Checkpoint{}); !errors.Is(err, ErrNoCheckpointKey) {
		t.Fatalf("VerifySignature = %v, want ErrNoCheckpointKey", err)
	}
}

func TestCheckpoint_SignAndVerify(t *testing.T) {
	c := testCheckpointer(t)
	sink := NewInMemorySink(100)
	appendN(t, sink, 3, "agent:billing")

	cp, result, err := c.Create(context.Background(), sink)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if !result.OK {
		t.Fatalf("the chain did not verify: %+v", result)
	}
	if cp.Seq == 0 || cp.Hash == "" || cp.Signature == "" {
		t.Fatalf("checkpoint = %+v, want a real seq, hash and signature", cp)
	}
	if err := c.VerifySignature(cp); err != nil {
		t.Fatalf("VerifySignature on a freshly created checkpoint: %v", err)
	}
}

func TestCheckpoint_AlteredContentsFailVerification(t *testing.T) {
	c := testCheckpointer(t)
	sink := NewInMemorySink(100)
	appendN(t, sink, 3, "agent:billing")
	cp, _, err := c.Create(context.Background(), sink)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	for name, altered := range map[string]Checkpoint{
		"hash":       {Seq: cp.Seq, Hash: "0000000000000000000000000000000000000000000000000000000000000000", CreatedAt: cp.CreatedAt, Signature: cp.Signature},
		"seq":        {Seq: cp.Seq + 1, Hash: cp.Hash, CreatedAt: cp.CreatedAt, Signature: cp.Signature},
		"created_at": {Seq: cp.Seq, Hash: cp.Hash, CreatedAt: cp.CreatedAt.Add(time.Hour), Signature: cp.Signature},
	} {
		if err := c.VerifySignature(altered); !errors.Is(err, ErrCheckpointSignature) {
			t.Fatalf("altering %s produced %v, want ErrCheckpointSignature", name, err)
		}
	}
}

func TestCheckpoint_ADifferentKeyDoesNotVerify(t *testing.T) {
	c := testCheckpointer(t)
	other, err := NewCheckpointer([]byte("ffffffffffffffffffffffffffffffff"))
	if err != nil {
		t.Fatalf("NewCheckpointer: %v", err)
	}
	sink := NewInMemorySink(100)
	appendN(t, sink, 2, "agent:billing")
	cp, _, err := c.Create(context.Background(), sink)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := other.VerifySignature(cp); !errors.Is(err, ErrCheckpointSignature) {
		t.Fatalf("a checkpoint verified under a different key: %v", err)
	}
}

// TestCheckpoint_RefusesToSignABrokenChain matters because the opposite
// is actively harmful: a signed statement that a broken chain was the
// tip would later look like proof the damage was legitimate history.
func TestCheckpoint_RefusesToSignABrokenChain(t *testing.T) {
	c := testCheckpointer(t)
	first := Event{Action: "agent.registered", AgentRef: "agent:billing", At: time.Now()}
	firstHash := chainHash(first, GenesisHash)
	tampered := Event{Action: "agent.killed", AgentRef: "agent:billing", At: time.Now()}

	store := fakeChainedStore{chain: Chain{
		StartsAtGenesis: true,
		Events: []ChainedEvent{
			{Event: first, Seq: 1, Hash: firstHash, PrevHash: GenesisHash},
			// Hash does not match the event, the shape a modified row has.
			{Event: tampered, Seq: 2, Hash: firstHash, PrevHash: firstHash},
		},
	}}

	_, result, err := c.Create(context.Background(), store)
	if err == nil {
		t.Fatal("Create signed a chain that does not verify")
	}
	if result.OK {
		t.Fatal("the result reported OK for a broken chain")
	}
}

// TestCheckpoint_CatchesAConsistentRewrite is the entire point of this
// file. The rewritten chain verifies perfectly against itself, because
// it is a valid chain over different events. Only the signed checkpoint
// knows it is the wrong history.
func TestCheckpoint_CatchesAConsistentRewrite(t *testing.T) {
	c := testCheckpointer(t)
	ctx := context.Background()

	original := NewInMemorySink(100)
	appendN(t, original, 4, "agent:billing")
	cp, _, err := c.Create(ctx, original)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// A completely rewritten history, chained correctly from genesis.
	rewritten := NewInMemorySink(100)
	appendN(t, rewritten, 4, "agent:innocent")

	plain, err := Verify(ctx, rewritten)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !plain.OK {
		t.Fatalf("the rewritten chain does not verify against itself, this test needs it to: %+v", plain)
	}

	out, err := c.VerifyAgainst(ctx, rewritten, cp)
	if err != nil {
		t.Fatalf("VerifyAgainst: %v", err)
	}
	if !out.OK {
		t.Fatal("the chain check reported a break, this test is about the case where it does not")
	}
	if out.MatchesCheckpoint {
		t.Fatal("a rewritten history matched the checkpoint, the anchor is not anchoring anything")
	}
	if out.CheckpointMismatch == "" {
		t.Fatal("no explanation of the mismatch, an operator needs to know what it means")
	}
}

func TestCheckpoint_MatchesAnUntouchedChainThatHasGrownSince(t *testing.T) {
	c := testCheckpointer(t)
	ctx := context.Background()
	sink := NewInMemorySink(100)
	appendN(t, sink, 3, "agent:billing")

	cp, _, err := c.Create(ctx, sink)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// The chain keeps growing, which is the normal case: a checkpointed
	// event is somewhere in the middle by the time anyone checks.
	appendN(t, sink, 5, "agent:payroll")

	out, err := c.VerifyAgainst(ctx, sink, cp)
	if err != nil {
		t.Fatalf("VerifyAgainst: %v", err)
	}
	if !out.MatchesCheckpoint {
		t.Fatalf("a chain that only grew stopped matching its checkpoint: %s", out.CheckpointMismatch)
	}
}

// TestCheckpoint_CatchesTruncationBelowTheAnchor covers the other shape:
// the checkpointed event is gone entirely.
func TestCheckpoint_CatchesTruncationBelowTheAnchor(t *testing.T) {
	c := testCheckpointer(t)
	ctx := context.Background()
	sink := NewInMemorySink(100)
	appendN(t, sink, 4, "agent:billing")

	cp, _, err := c.Create(ctx, sink)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	chain, err := sink.Chain(ctx)
	if err != nil {
		t.Fatalf("Chain: %v", err)
	}
	truncated := fakeChainedStore{chain: Chain{
		StartsAtGenesis: true,
		Events:          chain.Events[:2],
		Tip:             chain.Events[1].Hash,
	}}

	out, err := c.VerifyAgainst(ctx, truncated, cp)
	if err != nil {
		t.Fatalf("VerifyAgainst: %v", err)
	}
	if out.MatchesCheckpoint {
		t.Fatal("a truncated chain matched a checkpoint for an event it no longer contains")
	}
}

func TestInMemoryCheckpointStore(t *testing.T) {
	ctx := context.Background()
	s := NewInMemoryCheckpointStore()

	if _, err := s.Latest(ctx); !errors.Is(err, ErrNoCheckpoints) {
		t.Fatalf("Latest on an empty store = %v, want ErrNoCheckpoints", err)
	}
	for i := 1; i <= 3; i++ {
		if err := s.Save(ctx, Checkpoint{Seq: int64(i), Hash: "h", CreatedAt: time.Now()}); err != nil {
			t.Fatalf("Save: %v", err)
		}
	}
	latest, err := s.Latest(ctx)
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if latest.Seq != 3 {
		t.Fatalf("Latest seq = %d, want the most recent", latest.Seq)
	}
	list, err := s.List(ctx, 2)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("List(2) returned %d", len(list))
	}
}

func TestCheckpointerFromEnv(t *testing.T) {
	t.Setenv(envCheckpointKey, "")
	c, err := CheckpointerFromEnv()
	if err != nil {
		t.Fatalf("CheckpointerFromEnv: %v", err)
	}
	if c.Configured() {
		t.Fatal("configured with no key set")
	}

	t.Setenv(envCheckpointKey, "bm90LXZhbGlkLWJhc2U2NC1idXQtaXQtaXM=")
	if _, err := CheckpointerFromEnv(); err == nil {
		t.Fatal("a 26-byte key was accepted, the minimum is 32")
	}

	t.Setenv(envCheckpointKey, "!!!not base64!!!")
	if _, err := CheckpointerFromEnv(); err == nil {
		t.Fatal("a non-base64 key was accepted")
	}

	t.Setenv(envCheckpointKey, "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")
	c, err = CheckpointerFromEnv()
	if err != nil {
		t.Fatalf("CheckpointerFromEnv with a valid key: %v", err)
	}
	if !c.Configured() {
		t.Fatal("a valid 32-byte key did not configure the checkpointer")
	}
}
