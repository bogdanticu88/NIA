package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// This file is NIA's tamper-evident audit chain: every event, when
// it's written, gets a hash computed from its own data and the
// previous event's hash, and that hash is what gets stored alongside
// it. Verify (below) recomputes those hashes independently from the
// stored data and proves the chain is intact, or names exactly where
// it isn't. This is the security boundary, stated once here rather
// than scattered across doc comments, because it needs to be
// understood by anyone reading an audit trail, not just anyone
// reading this file:
//
//	Hash chaining provides tamper evidence.
//	It does not by itself prevent a privileged database administrator
//	from rewriting both the events and the chain.
//
// A privileged administrator with write access to audit_events (or
// direct filesystem/memory access, for InMemorySink) can delete an
// event and then recompute every hash after it to make the chain look
// intact again, the same way rewriting a git history and force-pushing
// makes the old commits disappear without a trace, unless someone
// independently kept the old tip. Verify catches an attacker who
// modifies, deletes, inserts, or reorders events without also
// recomputing the entire suffix of the chain that follows, which is
// the overwhelmingly more likely case (an attacker who can quietly and
// correctly rewrite an entire audit table's hash chain by hand already
// has the kind of access no application-level control stops), and it
// catches it without trusting anything the application that originally
// wrote the events claims, it only trusts the stored data and
// recomputes from there. Closing the "privileged rewrite" gap needs an
// external anchor the database itself can't rewrite: a periodic signed
// checkpoint published somewhere else, or WORM storage for the table.
// Neither exists yet. Chained (below) is deliberately the narrow
// interface a future checkpoint mechanism would need (read the current
// chain state), so adding one later doesn't mean redesigning this API,
// only adding a second consumer of it.

// GenesisHash is the defined prev_hash for the first event in a chain,
// a fixed, documented value rather than an empty string or a nil
// sentinel, so "this is genuinely the first event" and "this event's
// prev_hash was never set" are never ambiguous when read back from
// storage. It has no cryptographic meaning, it's not the hash of
// anything, it's a constant every implementation and every verifier
// agrees on, the same reason a git repository's first commit has "the
// zero SHA" as its stated parent rather than no parent field at all.
var GenesisHash = strings.Repeat("0", 64)

// canonicalize returns a deterministic byte representation of one
// event's data. Field order is fixed and explicit here, not left to
// encoding/json's struct field order, which is stable in practice but
// not a contract: if Event's field order in audit.go ever changed for
// an unrelated reason (gofmt, a refactor, adding a field), an implicit
// encoding would silently change the hash of every future event
// without changing anything security-relevant, breaking verification
// against every event written before that change. NUL bytes separate
// fields so that, e.g., Action="a" AgentRef="bc" and Action="ab"
// AgentRef="c" don't canonicalize to the same bytes.
//
// At is formatted as RFC3339Nano in UTC, not Go's default time.Time
// text form, so this produces the same bytes regardless of the
// machine's local timezone or how the time.Time value happened to be
// constructed, and it's truncated to microsecond precision first.
// PostgreSQL's TIMESTAMPTZ only stores microseconds, so a hash computed
// at write time from a Go time.Time carrying nanosecond precision
// would never match a hash recomputed after that same value made a
// round trip through the database, every single event would look
// "modified" the instant it was read back, not because anything was
// tampered with, only because Verify was comparing against precision
// that was never actually persisted. Truncating here, once, in the one
// function both the write path and the read path call, keeps both
// sides honest about what was really stored.
func canonicalize(evt Event) []byte {
	fields := []string{
		evt.Action,
		evt.AgentRef,
		evt.Operator,
		evt.Incident,
		evt.Detail,
		evt.At.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano),
	}
	return []byte(strings.Join(fields, "\x00"))
}

// chainHash computes the hash one event gets when it's appended after
// a predecessor whose own hash was prevHash. This is the one place the
// actual chaining algorithm lives, both the write path (InMemorySink
// and PostgresSink's Append) and the read path (Verify) call this same
// function, so there is exactly one definition of what a "correct"
// hash is, not two implementations that could quietly drift apart.
func chainHash(evt Event, prevHash string) string {
	h := sha256.New()
	h.Write(canonicalize(evt))
	h.Write([]byte("\x00"))
	h.Write([]byte(prevHash))
	return hex.EncodeToString(h.Sum(nil))
}

// ChainedEvent is one event together with the chain metadata Verify
// needs. Seq is the storage layer's own append-order identity (the
// Postgres row's id, or an in-memory monotonic counter), not the same
// thing as At: At is when the caller says the event happened, Seq is
// the order storage actually persisted it in, which is what the chain
// is built on. Hash and PrevHash are exactly what's stored, Verify
// never trusts them at face value, it recomputes Hash from Event and
// PrevHash and compares.
type ChainedEvent struct {
	Event
	Seq      int64
	Hash     string
	PrevHash string
}

// Chain is what a Chained store returns: the events in append order,
// plus whether Events[0], if present, is provably the actual first
// event this store ever chained. StartsAtGenesis is false in exactly
// two situations, both legitimate and both distinct from tampering:
// InMemorySink evicted older events past its capacity, so the window
// Verify sees is real but partial, or (not currently possible for
// either implementation in this codebase, reserved for a future
// windowed store) some other reason the true beginning of the chain
// isn't visible here. When it's false, Verify skips the genesis check
// on the first event rather than flagging a false break.
type Chain struct {
	Events          []ChainedEvent
	StartsAtGenesis bool

	// Tip is the last chain hash the store recorded separately from the
	// events themselves, PostgresSink's audit_chain_state.last_hash row.
	// Verify compares the final event's hash against it, which is what
	// catches the one tampering shape walking the events alone cannot:
	// clearing the hash column on a suffix of rows, or deleting the
	// newest rows outright, leaves the remaining events perfectly
	// self-consistent. The tip still points at a hash none of them
	// carries.
	//
	// Empty means this store keeps no separate tip and Verify skips
	// that check. How much the check is worth depends on the store: for
	// PostgresSink it's a different table an attacker has to remember
	// to rewrite too, for InMemorySink it's a field in the same struct
	// as the events, so it catches bugs and careless tampering, not an
	// attacker who already has the process's memory.
	Tip string
}

// Chained is the read side a Store can optionally implement to make
// its stored chain independently verifiable. Both InMemorySink and
// PostgresSink implement it. Kept as its own small interface, not
// folded into Store, because not every future Sink/Store
// implementation (a SIEM forwarder, say) necessarily has a queryable
// chain to read back, see audit.go's own doc comment on InMemorySink
// being for local dev and PostgresSink being the real backend.
type Chained interface {
	Chain(ctx context.Context) (Chain, error)
}

// ChainBreak is one specific place Verify found the chain not to hold
// together. Seq identifies which event, Reason says what's wrong in
// plain language, not an error code, this is meant to be read directly
// by an operator running niactl audit verify, not decoded by a caller.
type ChainBreak struct {
	Seq    int64
	Reason string
}

// VerifyResult is Verify's full accounting, not just a pass/fail bool.
// Checked is how many events actually had their hash and chain linkage
// checked. Skipped is how many events were excluded because they
// predate hash chaining being enabled (Hash == "", see PostgresSink's
// migration comment), named explicitly rather than silently treated as
// either valid or invalid, there was never a hash recorded for them to
// check against. Breaks is empty and OK is true only when every
// checked event's hash matches its own data and every checked event's
// prev_hash matches the event before it.
type VerifyResult struct {
	OK      bool
	Checked int
	Skipped int
	Breaks  []ChainBreak
}

// Verify walks a chain in the storage layer's own append order and
// proves, independently of whatever the application logic that wrote
// these events believed, that every event's recorded hash matches a
// hash recomputed from that event's own stored data (catches
// modification), and that every event's recorded prev_hash matches the
// immediately preceding event's recorded hash (catches deletion,
// insertion, and reordering, all three show up the same way here: a
// break in the linkage between consecutive entries, see this
// function's own tests in chain_test.go for one of each). Verify never
// reads or trusts anything about how or when it's called, it only
// reads what Chain returns and recomputes from there, that's what
// "verification does not depend on trusting the application logic
// that originally created the events" means in practice: this function
// would catch a bug in Append itself just as readily as a deliberate
// attack, both look the same, a hash that doesn't match its data.
func Verify(ctx context.Context, store Chained) (VerifyResult, error) {
	chain, err := store.Chain(ctx)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("audit: reading chain: %w", err)
	}

	result := VerifyResult{OK: true}
	var prevHash string
	var lastSeq int64
	haveChainStart := false

	for _, e := range chain.Events {
		if e.Hash == "" {
			// Predates hash chaining being enabled on this store, never
			// had a hash computed for it, see this file's own doc
			// comment and PostgresSink's migration comment. Legitimate
			// only as a prefix: chaining was switched on at one moment
			// in this table's life and never switched off, so every
			// event after the first hashed one was written with a hash.
			// An empty hash after that point is not a legacy row, it is
			// a row whose hash column was cleared, which is exactly how
			// an attacker would try to make a modified event skip
			// verification instead of failing it.
			if haveChainStart {
				result.OK = false
				result.Breaks = append(result.Breaks, ChainBreak{
					Seq:    e.Seq,
					Reason: "hash is empty on an event that follows a hashed event: chaining is never switched back off, so this event's hash was cleared after it was written",
				})
			}
			result.Skipped++
			continue
		}

		if got := chainHash(e.Event, e.PrevHash); got != e.Hash {
			result.OK = false
			result.Breaks = append(result.Breaks, ChainBreak{
				Seq:    e.Seq,
				Reason: "recorded hash does not match a hash recomputed from this event's own stored data: the event was modified after it was written",
			})
		}

		switch {
		case !haveChainStart && chain.StartsAtGenesis:
			if e.PrevHash != GenesisHash {
				result.OK = false
				result.Breaks = append(result.Breaks, ChainBreak{
					Seq:    e.Seq,
					Reason: "first event in the chain does not chain from the defined genesis value",
				})
			}
		case haveChainStart:
			if e.PrevHash != prevHash {
				result.OK = false
				result.Breaks = append(result.Breaks, ChainBreak{
					Seq:    e.Seq,
					Reason: "prev_hash does not match the immediately preceding event's recorded hash: an event was inserted, deleted, or reordered between them",
				})
			}
		}
		haveChainStart = true

		result.Checked++
		prevHash = e.Hash
		lastSeq = e.Seq
	}

	// The tip check. Everything above verifies the events against each
	// other, which is self-consistent by construction if an attacker
	// truncates the chain: delete the newest events, or blank their
	// hashes, and what's left still links up perfectly. Comparing the
	// last surviving hash against the tip the store recorded somewhere
	// else is what makes that visible, see Chain.Tip's own doc comment
	// for how much that's worth per implementation.
	switch {
	case chain.Tip == "":
		// This store keeps no separate tip, nothing further to check.
	case result.Checked == 0:
		if chain.Tip != GenesisHash {
			result.OK = false
			result.Breaks = append(result.Breaks, ChainBreak{
				Reason: "the store recorded a chain tip but no hashed event is left to match it: every chained event was deleted or had its hash cleared",
			})
		}
	case prevHash != chain.Tip:
		result.OK = false
		result.Breaks = append(result.Breaks, ChainBreak{
			Seq:    lastSeq,
			Reason: "the last event's hash does not match the chain tip the store recorded separately: one or more events were removed from the end of the chain",
		})
	}

	return result, nil
}
