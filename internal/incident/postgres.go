package incident

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	_ "github.com/lib/pq"

	"github.com/bogdanticu88/nia/internal/dbschema"
)

// incidentSchemaSQL creates the one table PostgresStore needs, same
// posture as every other PostgresX here.
//
// signals is JSONB rather than a child table. The shape is a short list
// of name/weight pairs written once and read whole, never queried by
// individual signal, so a second table would buy a join and cost the
// thing that actually matters here: an incident record is evidence, and
// evidence is easier to trust when one row is the whole record.
const incidentSchemaSQL = `
CREATE TABLE IF NOT EXISTS incidents (
	id           TEXT PRIMARY KEY,
	agent_ref    TEXT NOT NULL,
	incident_ref TEXT NOT NULL DEFAULT '',
	action       TEXT NOT NULL,
	risk_value   DOUBLE PRECISION NOT NULL DEFAULT 0,
	cumulative   DOUBLE PRECISION NOT NULL DEFAULT 0,
	signals      JSONB NOT NULL DEFAULT '[]'::jsonb,
	reason       TEXT NOT NULL DEFAULT '',
	created_at   TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS incidents_agent_ref_created_at_idx ON incidents (agent_ref, created_at);
CREATE INDEX IF NOT EXISTS incidents_created_at_idx ON incidents (created_at);
`

// Pool limits, same numbers and reasoning as every other PostgresX
// constructor here, see internal/audit/postgres_sink.go's own block.
const (
	maxOpenConns    = 8
	maxIdleConns    = 4
	connMaxLifetime = 30 * time.Minute
)

// PostgresStore is the durable incident store. Until it existed, every
// containment decision NIA made was recorded in a map that died with the
// process, which is a strange property for the one record an incident
// review is supposed to start from: restart the gateway and the evidence
// for why an agent was killed an hour ago is gone, leaving only the
// audit line saying that it was. Across replicas it was worse, GET
// /incidents answered from whichever gateway happened to take the
// request and each had seen different containment decisions.
type PostgresStore struct {
	db *sql.DB
}

func NewPostgresStore(ctx context.Context, dsn string) (*PostgresStore, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("incident: opening postgres: %w", err)
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("incident: postgres unreachable: %w", err)
	}
	if err := dbschema.Apply(ctx, db, "incident", incidentSchemaSQL); err != nil {
		db.Close()
		return nil, err
	}
	db.SetMaxOpenConns(maxOpenConns)
	db.SetMaxIdleConns(maxIdleConns)
	db.SetConnMaxLifetime(connMaxLifetime)
	return &PostgresStore{db: db}, nil
}

func (s *PostgresStore) Close() error { return s.db.Close() }

func (s *PostgresStore) Create(ctx context.Context, in Incident) (Incident, error) {
	if in.ID == "" {
		id, err := newID()
		if err != nil {
			return Incident{}, fmt.Errorf("incident: generating id: %w", err)
		}
		in.ID = id
	}
	if in.CreatedAt.IsZero() {
		in.CreatedAt = time.Now()
	}
	signals, err := json.Marshal(in.Signals)
	if err != nil {
		return Incident{}, fmt.Errorf("incident: encoding signals: %w", err)
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO incidents (id, agent_ref, incident_ref, action, risk_value, cumulative, signals, reason, created_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		in.ID, in.AgentRef, in.IncidentRef, in.Action, in.RiskValue, in.Cumulative, signals, in.Reason, in.CreatedAt,
	); err != nil {
		return Incident{}, fmt.Errorf("incident: creating record for %s: %w", in.AgentRef, err)
	}
	return in, nil
}

func (s *PostgresStore) Get(ctx context.Context, id string) (Incident, error) {
	row := s.db.QueryRowContext(ctx, incidentSelectColumns+` FROM incidents WHERE id = $1`, id)
	in, err := scanIncident(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Incident{}, ErrNotFound
	}
	if err != nil {
		return Incident{}, fmt.Errorf("incident: getting %s: %w", id, err)
	}
	return in, nil
}

// List returns incidents oldest first, matching InMemoryStore's
// documented order. A limit applies to the most recent ones, which is
// the useful half of a capped read during an investigation, and they
// are then reversed back into ascending order so both implementations
// answer the same shape.
func (s *PostgresStore) List(ctx context.Context, agentRef string, limit int) ([]Incident, error) {
	query := incidentSelectColumns + ` FROM incidents`
	args := []any{}
	if agentRef != "" {
		query += ` WHERE agent_ref = $1`
		args = append(args, agentRef)
	}
	query += ` ORDER BY created_at DESC, id DESC`
	if limit > 0 {
		query += fmt.Sprintf(` LIMIT $%d`, len(args)+1)
		args = append(args, limit)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("incident: listing: %w", err)
	}
	defer rows.Close()

	out := make([]Incident, 0)
	for rows.Next() {
		in, err := scanIncident(rows)
		if err != nil {
			return nil, fmt.Errorf("incident: listing: %w", err)
		}
		out = append(out, in)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("incident: listing: %w", err)
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}

const incidentSelectColumns = `SELECT id, agent_ref, incident_ref, action, risk_value, cumulative, signals, reason, created_at`

type rowScanner interface {
	Scan(dest ...any) error
}

func scanIncident(row rowScanner) (Incident, error) {
	var in Incident
	var signals []byte
	if err := row.Scan(
		&in.ID, &in.AgentRef, &in.IncidentRef, &in.Action,
		&in.RiskValue, &in.Cumulative, &signals, &in.Reason, &in.CreatedAt,
	); err != nil {
		return Incident{}, err
	}
	if len(signals) > 0 {
		if err := json.Unmarshal(signals, &in.Signals); err != nil {
			return Incident{}, fmt.Errorf("decoding signals for %s: %w", in.ID, err)
		}
	}
	return in, nil
}

// newID matches InMemoryStore's own format so an id is recognisable as
// an incident id regardless of which store produced it.
func newID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "inc-" + hex.EncodeToString(b), nil
}

var _ Store = (*PostgresStore)(nil)
