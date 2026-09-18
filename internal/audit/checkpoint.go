package audit

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"
)

// This file is the external anchor chain.go's own doc comment said was
// missing. Restating the boundary it closes, because the difference is
// easy to lose:
//
// Hash chaining catches an attacker who modifies, deletes, inserts or
// reorders events without recomputing the rest of the chain. It does
// not catch one who rewrites the events and every hash after them
// consistently, or who replaces the table wholesale. Verify would walk
// the rewritten chain and report it intact, because it is intact: it is
// a perfectly valid chain over the wrong events.
//
// A checkpoint is a signed statement that at some moment the chain's tip
// was a particular hash at a particular sequence number. Rewriting
// history now also requires forging that signature, which requires the
// signing key, which is not in the database. An attacker with full write
// access to audit_events can still destroy the trail, nothing at this
// layer prevents that, but they can no longer rewrite it into a
// different history that verifies.
//
// What this deliberately does not do is make checkpoints automatic.
// Creating one is an explicit operation (POST /audit/checkpoint, niactl
// audit checkpoint), because a checkpoint written by the same process on
// the same schedule as the events it covers, into the same database, is
// most of the ceremony and little of the guarantee. The value comes from
// an operator taking them at meaningful moments and keeping them
// somewhere the database cannot reach, which is a deployment practice
// this package can support but cannot enforce.

// Checkpoint is a signed assertion about the chain's tip at a moment in
// time. Seq and Hash identify the event that was last in the chain,
// CreatedAt is when the assertion was made, and Signature is an HMAC
// over all three.
//
// HMAC rather than a public-key signature: the party creating
// checkpoints and the party verifying them are the same operator with
// the same secret, so asymmetric keys would buy separation nobody here
// is asking for and add key distribution nobody wants. If checkpoints
// ever need to be verifiable by someone who must not be able to create
// them, that is the moment to switch.
type Checkpoint struct {
	Seq       int64     `json:"seq"`
	Hash      string    `json:"hash"`
	CreatedAt time.Time `json:"created_at"`
	Signature string    `json:"signature"`
}

// ErrNoCheckpointKey is returned when a checkpoint operation is asked
// for on a process that has no signing key configured. Distinct from a
// verification failure on purpose: "this deployment does not do
// checkpoints" and "this checkpoint is forged" must never be confused
// for each other.
var ErrNoCheckpointKey = errors.New("audit: no checkpoint signing key is configured")

// ErrCheckpointSignature is returned when a checkpoint's signature does
// not match its contents, which means either the checkpoint was altered
// or it was signed with a different key.
var ErrCheckpointSignature = errors.New("audit: checkpoint signature does not match its contents")

// ErrChainDivergedFromCheckpoint is returned when the chain no longer
// contains the event a valid checkpoint attests to. This is the finding
// the whole file exists to produce: the chain may verify perfectly
// against itself and still be a different history from the one that was
// signed.
var ErrChainDivergedFromCheckpoint = errors.New("audit: the chain does not match a signed checkpoint")

// minCheckpointKeyLen matches the minimum internal/policy requires of
// the Tessera signing key, for the same reason: a short HMAC key is the
// kind of thing that looks configured and is not.
const minCheckpointKeyLen = 32

// Checkpointer creates and verifies checkpoints with one signing key.
// A nil Checkpointer is the "not configured" state and every method
// returns ErrNoCheckpointKey, so a caller can hold one unconditionally.
type Checkpointer struct {
	key []byte
}

// NewCheckpointer rejects a key shorter than 32 bytes rather than
// accepting whatever it is given.
func NewCheckpointer(key []byte) (*Checkpointer, error) {
	if len(key) < minCheckpointKeyLen {
		return nil, fmt.Errorf("audit: checkpoint signing key must be at least %d bytes, got %d", minCheckpointKeyLen, len(key))
	}
	return &Checkpointer{key: key}, nil
}

// Configured reports whether checkpointing is available on this process.
func (c *Checkpointer) Configured() bool { return c != nil && len(c.key) >= minCheckpointKeyLen }

// signable is the exact byte sequence a signature covers. Explicit and
// field-separated for the same reason canonicalize is: an implicit
// encoding would silently change what a signature means the day a field
// is added, and every previously issued checkpoint would stop verifying
// for a reason that has nothing to do with tampering.
func signable(seq int64, hash string, at time.Time) []byte {
	return []byte(strconv.FormatInt(seq, 10) + "\x00" + hash + "\x00" + at.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano))
}

func (c *Checkpointer) sign(seq int64, hash string, at time.Time) string {
	mac := hmac.New(sha256.New, c.key)
	mac.Write(signable(seq, hash, at))
	return hex.EncodeToString(mac.Sum(nil))
}

// Create reads the store's current chain and signs its tip.
//
// It refuses to checkpoint a chain that does not currently verify. A
// signed statement that a broken chain was the tip is worse than no
// statement: it would later look like proof that the damage was
// legitimate history.
func (c *Checkpointer) Create(ctx context.Context, store Chained) (Checkpoint, VerifyResult, error) {
	if !c.Configured() {
		return Checkpoint{}, VerifyResult{}, ErrNoCheckpointKey
	}

	result, err := Verify(ctx, store)
	if err != nil {
		return Checkpoint{}, VerifyResult{}, err
	}
	if !result.OK {
		return Checkpoint{}, result, fmt.Errorf("audit: refusing to checkpoint a chain that does not verify, %d break(s) found", len(result.Breaks))
	}

	chain, err := store.Chain(ctx)
	if err != nil {
		return Checkpoint{}, result, fmt.Errorf("audit: reading chain: %w", err)
	}

	var tipSeq int64
	tipHash := GenesisHash
	for i := len(chain.Events) - 1; i >= 0; i-- {
		if chain.Events[i].Hash != "" {
			tipSeq, tipHash = chain.Events[i].Seq, chain.Events[i].Hash
			break
		}
	}

	cp := Checkpoint{Seq: tipSeq, Hash: tipHash, CreatedAt: time.Now().UTC().Truncate(time.Microsecond)}
	cp.Signature = c.sign(cp.Seq, cp.Hash, cp.CreatedAt)
	return cp, result, nil
}

// VerifySignature checks that a checkpoint is one this key produced and
// that its contents have not been altered since.
func (c *Checkpointer) VerifySignature(cp Checkpoint) error {
	if !c.Configured() {
		return ErrNoCheckpointKey
	}
	want := c.sign(cp.Seq, cp.Hash, cp.CreatedAt)
	if !hmac.Equal([]byte(want), []byte(cp.Signature)) {
		return ErrCheckpointSignature
	}
	return nil
}

// CheckpointVerifyResult is what VerifyAgainst reports: the ordinary
// chain verification, plus whether the chain still agrees with the
// signed checkpoint.
//
// The two are genuinely separate answers. ChainOK false means the chain
// broke on its own terms. MatchesCheckpoint false with ChainOK true is
// the case only a checkpoint can surface: a chain that is internally
// perfect and is not the history that was signed.
type CheckpointVerifyResult struct {
	VerifyResult
	CheckpointSeq      int64  `json:"checkpoint_seq"`
	CheckpointHash     string `json:"checkpoint_hash"`
	CheckpointAt       string `json:"checkpoint_at"`
	MatchesCheckpoint  bool   `json:"matches_checkpoint"`
	CheckpointMismatch string `json:"checkpoint_mismatch,omitempty"`
}

// VerifyAgainst verifies the chain and then confirms it still contains
// the event the checkpoint attests to, with the same hash.
//
// Deliberately not "the tip still equals the checkpoint's hash": the
// chain grows, so the checkpointed event is normally somewhere in the
// middle by the time anyone checks. What must hold is that the event at
// that sequence number is still the one that was signed.
func (c *Checkpointer) VerifyAgainst(ctx context.Context, store Chained, cp Checkpoint) (CheckpointVerifyResult, error) {
	if !c.Configured() {
		return CheckpointVerifyResult{}, ErrNoCheckpointKey
	}
	if err := c.VerifySignature(cp); err != nil {
		return CheckpointVerifyResult{}, err
	}

	result, err := Verify(ctx, store)
	if err != nil {
		return CheckpointVerifyResult{}, err
	}
	out := CheckpointVerifyResult{
		VerifyResult:   result,
		CheckpointSeq:  cp.Seq,
		CheckpointHash: cp.Hash,
		CheckpointAt:   cp.CreatedAt.Format(time.RFC3339Nano),
	}

	chain, err := store.Chain(ctx)
	if err != nil {
		return out, fmt.Errorf("audit: reading chain: %w", err)
	}

	// A checkpoint over an empty chain attests to the genesis value and
	// there is no event to find.
	if cp.Seq == 0 && cp.Hash == GenesisHash {
		out.MatchesCheckpoint = true
		return out, nil
	}

	for _, e := range chain.Events {
		if e.Seq != cp.Seq {
			continue
		}
		if e.Hash == cp.Hash {
			out.MatchesCheckpoint = true
			return out, nil
		}
		out.CheckpointMismatch = fmt.Sprintf("event %d is present but its hash is %s, the checkpoint signed %s: the events at and before this point were rewritten", cp.Seq, e.Hash, cp.Hash)
		return out, nil
	}

	out.CheckpointMismatch = fmt.Sprintf("event %d is not in the chain at all, the checkpoint signed hash %s for it: the trail was truncated or replaced below that point", cp.Seq, cp.Hash)
	return out, nil
}
