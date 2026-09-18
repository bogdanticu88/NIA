package incident

import (
	"context"
	"os"
	"strings"
)

// envDatabaseURL points the incident store at Postgres. Unset means
// InMemoryStore, which is where every containment record lived until
// this existed: a map that died with the process.
//
// That default is worth stating bluntly because of what these records
// are. An incident record is the evidence for why NIA killed or
// revoked an agent, the thing a review starts from, and losing it on a
// restart leaves only the audit line saying containment happened
// without the risk value, the signals, or the cumulative total that
// caused it. Across replicas it also meant GET /incidents answered
// from whichever gateway took the request.
const envDatabaseURL = "NIA_INCIDENT_DATABASE_URL"

// FromEnv builds the Store this process should use and reports whether
// it is the shared one. An unreachable database is an error, not a
// silent fall back, same reasoning as every other FromEnv here.
func FromEnv(ctx context.Context) (store Store, shared bool, err error) {
	dsn := strings.TrimSpace(os.Getenv(envDatabaseURL))
	if dsn == "" {
		return NewInMemoryStore(), false, nil
	}
	pg, err := NewPostgresStore(ctx, dsn)
	if err != nil {
		return nil, false, err
	}
	return pg, true, nil
}
