package registry

import (
	"context"
	"os"
	"strings"
)

// envDatabaseURL points the agent inventory at Postgres. Unset means
// InMemoryAgentRegistry, this process's own map, same in-memory-by-
// default posture as every other FromEnv here.
//
// What it changes is narrower than the audit or credential stores but
// not cosmetic: with it unset and more than one cmd/api replica, an
// agent registered through one replica is a 404 on the other, and
// niactl list shows a different inventory depending on which one
// answers. No authorization decision depends on it, kill state is read
// live from the policy client, so this is inventory and
// investigability rather than enforcement.
const envDatabaseURL = "NIA_REGISTRY_DATABASE_URL"

// FromEnv builds the AgentRegistry this process should use, and reports
// whether it is the shared one so a caller can log which it got. An
// unreachable database is an error rather than a silent fall back to
// the in-memory registry: a deployment that set the variable wants a
// shared inventory, and quietly giving it a private one would look
// identical until two replicas disagreed.
func FromEnv(ctx context.Context) (reg AgentRegistry, shared bool, err error) {
	dsn := strings.TrimSpace(os.Getenv(envDatabaseURL))
	if dsn == "" {
		return NewInMemoryAgentRegistry(), false, nil
	}
	pg, err := NewPostgresAgentRegistry(ctx, dsn)
	if err != nil {
		return nil, false, err
	}
	return pg, true, nil
}
