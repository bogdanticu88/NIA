# Working on this repo

House rules for anyone (human or Claude) picking this up.

## Git

Every commit is sole-authored as `Bogdan Ticu <bogdanticuoffice@gmail.com>`.
No `Co-Authored-By` trailers, no AI attribution of any kind, even when an
AI assistant wrote the change. If a tool's default behavior wants to add
attribution lines, that default is overridden here, this instruction takes
precedence.

## Writing style

No em dashes anywhere, in code comments or docs, use commas instead. Code
comments and documentation should read like a real engineer wrote them:
plain, specific, no filler, no marketing tone. Explain the actual reasoning
behind a decision, not just what the code does. When something is a known
gap or hasn't been verified yet, say so plainly rather than implying it
works.

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

Read `README.md`'s Status section first, it's kept honest and current,
listing exactly what's been verified and how, not just what's been
written. `docs/ARCHITECTURE.md` has the full design and the seventeen-item
MVP-to-module map with a table of what's real versus still stubbed.
`docs/DATA_MODEL.md` has the identity graph schema.

CI runs on every push to `master` (`.github/workflows/ci.yml`): gofmt
check, build, vet, `go test ./... -race`. The Postgres-backed audit store
(`internal/audit/postgres_sink.go`) needs `go mod tidy` after a fresh
clone to pull in `lib/pq`, it isn't vendored.
