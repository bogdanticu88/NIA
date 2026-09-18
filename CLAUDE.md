# Working on this repo

House rules for anyone (human or Claude) picking this up.

## Git

Every commit is sole-authored as `Bogdan Ticu <bogdanticuoffice@gmail.com>`.
No `Co-Authored-By` trailers, no AI attribution of any kind, even when an
AI assistant wrote the change. If a tool's default behavior wants to add
attribution lines, that default is overridden here, this instruction takes
precedence.

Commit messages follow the shape the log already has, and the easiest way
to get it right is to read the last few before writing one. Subject in the
imperative, sentence case, no `feat:`/`fix:`-style prefixes, a second
clause after a comma when one thing genuinely needs saying alongside the
other. Body in prose paragraphs, not bullets: what was wrong, what changed,
why it was done that way, and at the end what was actually run to verify
it. Wrap around 72 to 80 columns.

When a piece of work is one of the numbered phases the README tracks, put
`phase N` at the end of the subject (`..., phase 9`), never at the front,
and use the same number the README entry uses. Do not invent a separate
numbering for a plan or a working session, there is one sequence and it
lives in the README.

## Writing style

No em dashes anywhere, in code comments or docs, use commas instead. Code
comments and documentation should read like a real engineer wrote them:
plain, specific, no filler, no marketing tone. Explain the actual reasoning
behind a decision, not just what the code does. When something is a known
gap or hasn't been verified yet, say so plainly rather than implying it
works.

`CHANGELOG.md` has conventions of its own, and they matter because that
log is the honest record of what has actually been done. It used to live
in the README's Status section and moved out when that page got too long
to scan; the conventions came with it unchanged.
One entry per phase, numbered sequentially, and never two entries sharing
a number: if a pass produced three separable pieces of work, those are
three phases, not one phase with three bullets. The reverse is fine, a
single commit can cover several phases (see `9591ad2`, whose four items
are phases 13 to 16). Verification belongs at the end of the entry it
verifies, not collected into a separate bullet of its own. What a phase
deliberately did not do, and what it left open, goes inside that phase's
entry too. No bold, the file does not use it anywhere else.

## Verification standard

Don't claim something works without having actually run it. "It compiles"
is not "it works." Before calling a piece of work done: build it, run the
tests, and where the change touches something with real infrastructure
behind it (a database, another service, a container stack), run it against
the real thing at least once, not just against an in-memory stand-in. Two
genuine verification passes before moving on to the next piece of work,
not one. If a claim in a README or doc comment can't actually be backed up
yet, mark it as unverified instead of asserting it.

## This repo specifically

NIA is a Go service (agent security control plane). It depends on
[Tessera](https://github.com/bogdanticu88/Tessera) as its policy engine,
expected to be checked out as a sibling directory (`../tessera` relative
to this repo, see `deployments/docker-compose.yml`'s build context for
`tessera`).

Read `CHANGELOG.md` first, it's kept honest and current, listing exactly
what's been verified and how, not just what's been written. `README.md`
is the landing page: the hook, a real transcript, and a quickstart, with
the detail linked rather than inlined. `docs/ARCHITECTURE.md` has the
full design, the seventeen-item MVP-to-module map with a table of what's
real versus still stubbed, and the distributed-state table.
`docs/DATA_MODEL.md` has the identity graph schema. `docs/RUNNING.md`
has the full local setup.

CI runs on every push to `master` (`.github/workflows/ci.yml`): gofmt
check, build, vet, `go test ./... -race`. The Postgres-backed audit store
(`internal/audit/postgres_sink.go`) needs `go mod tidy` after a fresh
clone to pull in `lib/pq`, it isn't vendored.
