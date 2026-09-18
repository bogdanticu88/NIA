# Running NIA locally

The full local setup, moved out of README.md so the landing page can carry a short quickstart instead. This is the complete version: every `niactl` command, and the two-process gotchas that are easy to hit and hard to diagnose from the error alone.

Read the "Two processes, one backend" notes below before concluding something is broken. A 403 on every gateway call, or a 401 saying the caller identity could not be resolved, is usually two processes each talking to their own private in-memory default rather than a bug.

* * *

```bash
go build ./...
go vet ./...
go test ./...

# in one terminal
go run ./cmd/api

# in another
go run ./cmd/gateway

# register an agent
go run ./cmd/niactl register -ref agent:billing-reconciler -owner bogdan -purpose "reconciles invoices nightly"

# list what's registered
go run ./cmd/niactl list

# register a tool it's allowed to call
go run ./cmd/niactl tool register -name invoice-lookup -transport http -risk read_only -owner bogdan

# issue it a credential
go run ./cmd/niactl credential issue -ref agent:billing-reconciler -kind api_key -ttl 24h

# revoke one key without touching the agent itself
go run ./cmd/niactl credential revoke -id <credential_id> -reason "key leaked in a log"

# pull the kill switch, the bigger hammer, for when the agent itself is compromised
go run ./cmd/niactl kill -ref agent:billing-reconciler -incident INC-001

# review what happened to it
go run ./cmd/niactl audit -ref agent:billing-reconciler

# grant the agent access to that tool, the register and grant calls above already added both
# to the identity graph on their own, agent registration and tool registration add their own
# nodes, this grant adds the edge between them, nothing here needs graph add-node/add-edge by hand
go run ./cmd/niactl grant write -ref agent:billing-reconciler -kind tool -object invoice-lookup

# what could this agent reach if it were compromised right now
go run ./cmd/niactl graph reachable -id agent:billing-reconciler

# the same question, summarized: total reachable, a count by kind, and a HIGH/MEDIUM/LOW severity call
go run ./cmd/niactl graph blast-radius -id agent:billing-reconciler

# add a human as the accountable owner, nothing else creates Human nodes on its own
go run ./cmd/niactl graph add-node -id human:bogdan -kind human
go run ./cmd/niactl graph add-edge -from human:bogdan -to agent:billing-reconciler -kind owns

# call the gateway directly the way an MCP-aware caller would
go run ./cmd/niactl gateway call -ref agent:billing-reconciler -tool invoice-lookup

# drive the whole loop end to end: registration, grants, a scripted attack sequence,
# and, if the gateway was started with NIA_RISK_FLAG_AT / NIA_RISK_REVOKE_AT / NIA_RISK_KILL_AT
# set low enough, a real kill partway through and a real denial on the next call
go run ./cmd/niactl simulate attack -scenario agent-hijack

# review the structured incident records that scenario's containment decisions created
# (only meaningful if the gateway had risk thresholds set, see above)
go run ./cmd/niactl incident list -ref agent:invoice-agent

# one report: identity, credentials, grants, recent audit, blast radius, and a
# best-effort look at the gateway's own risk view for this agent, all in one place
go run ./cmd/niactl agent inspect -ref agent:billing-reconciler

# just the gateway's risk view: cumulative risk, thresholds, recent incidents
go run ./cmd/niactl risk -ref agent:billing-reconciler

# scrape either process's counters and gauges directly
curl http://localhost:8080/metrics
curl http://localhost:8081/metrics
```

Most of the commands above run fine against the in-memory policy client, the default, no Tessera, OpenFGA, or Postgres required, because they only ever talk to `cmd/api`. `gateway call` and `simulate attack` are the exception, worth being precise about rather than leaving as an assumption: `cmd/api` and `cmd/gateway` are two separate OS processes, and the in-memory default is exactly that, in-memory, private to whichever process constructed it. Point both at the unconfigured default and a grant written through `cmd/api` is invisible to `cmd/gateway`'s own policy check, every gateway call comes back 403, not because anything is broken, because there's genuinely nothing shared between them to check against. `niactl register` / `grant write` / `kill` and the rest still work standalone against `cmd/api` either way, it's specifically the two-process, grant-then-call-the-gateway path that needs a real shared backend. Tessera is that backend, and it doesn't need OpenFGA behind it to serve that purpose: point both `cmd/api` and `cmd/gateway` at one running `Tessera.Service` (`NIA_TESSERA_BASE_URL`, the same `NIA_TESSERA_JWT_SIGNING_KEY` it was started with, and, only if it isn't running with its own defaults, `NIA_TESSERA_JWT_ISSUER` / `NIA_TESSERA_JWT_AUDIENCE`) and Tessera's own `InMemoryAuthorizationStore` fallback (unset `OPENFGA_API_URL`) is enough of a shared backend for `gateway call` and `simulate attack` to actually work end to end, no live OpenFGA needed, that's how the "See it work" transcript above was captured. See `internal/policy/from_env.go` for the full env var list and defaults.

The same two-process gap exists for credentials now that `credentialResolver` is the gateway's default resolver, found while verifying this pass rather than assumed: `credentials.FromEnv` follows the exact same "unset means a private in-memory default" pattern `policy.FromEnv` does, so a credential issued through `cmd/api` (`credential issue`, or `simulate attack`'s own setup step) is invisible to `cmd/gateway`'s `credentialResolver.Verify`, every gateway call gets a 401 "could not resolve caller identity", again not because anything is broken, because there's nothing shared to verify against. Set `NIA_CREDENTIALS_DATABASE_URL` to the same Postgres connection string on both `cmd/api` and `cmd/gateway` to fix it, confirmed against the local Postgres this was verified with: register an agent, issue it a credential through `cmd/api`, present that credential to `cmd/gateway`, get a real 200, kill the agent through `cmd/api`, present the same credential again, get a real 401, restore, confirm `GET /agents/{ref}` reports active again. `deployments/docker-compose.yml` below already points both services at the stack's shared `postgres`, so this is only something to notice running the two processes by hand outside compose.

`deployments/docker-compose.yml` brings up the full stack, NIA's two services plus Tessera, OpenFGA, and Postgres, see CHANGELOG.md for what's actually been confirmed. OpenFGA needs a store and an authorization model before Tessera can use it, which can't be baked into compose (a store only gets an id once OpenFGA is already running): bring up `postgres` and `openfga` first, run `deployments/bootstrap-openfga.sh`, add the store id it prints to `.env` as `TESSERA_OPENFGA_STORE_ID`, then bring up the rest. The stack's `postgres` service also now backs the audit trail (`NIA_AUDIT_DATABASE_URL`, hardcoded in `docker-compose.yml`, it isn't a secret), no extra setup needed for that part, just `go mod tidy` first if this is the first build since `internal/audit/postgres_sink.go` was added, it pulls in `lib/pq`.
