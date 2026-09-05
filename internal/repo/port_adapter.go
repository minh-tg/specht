package repo

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/xMinhx/specht/internal/db/sqlc"
	"github.com/xMinhx/specht/internal/port"
)

// ---------- string/UUID helpers (adapter boundary) ----------

// parseID converts a port string ID to pgtype.UUID. Ports carry string IDs;
// UUID parsing happens once here at the adapter boundary.
func parseID(id string) (pgtype.UUID, error) {
	u, err := uuid.Parse(id)
	if err != nil {
		return pgtype.UUID{}, fmt.Errorf("invalid id %q: %w", id, err)
	}
	return pgtype.UUID{Bytes: u, Valid: true}, nil
}

func mustParseID(id string) pgtype.UUID {
	u, _ := parseID(id)
	return u
}

func toUUID(id pgtype.UUID) string {
	return uuid.UUID(id.Bytes).String()
}

func uuidFromTime(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: t, Valid: true}
}

func textPtrFromString(s *string) pgtype.Text {
	if s == nil || *s == "" {
		return pgtype.Text{Valid: false}
	}
	return pgtype.Text{String: *s, Valid: true}
}

func stringFromTextPtr(t pgtype.Text) *string {
	if !t.Valid {
		return nil
	}
	s := t.String
	return &s
}

func uuidPtrFromString(s *string) pgtype.UUID {
	if s == nil || *s == "" {
		return pgtype.UUID{Valid: false}
	}
	return mustParseID(*s)
}

func stringPtrFromUUID(u pgtype.UUID) *string {
	if !u.Valid {
		return nil
	}
	s := toUUID(u)
	return &s
}

func timestamptzPtrFromTime(t *time.Time) pgtype.Timestamptz {
	if t == nil {
		return pgtype.Timestamptz{Valid: false}
	}
	return pgtype.Timestamptz{Time: *t, Valid: true}
}

func timePtrFromTimestamptz(t pgtype.Timestamptz) *time.Time {
	if !t.Valid {
		return nil
	}
	tt := t.Time
	return &tt
}

// strVal returns the string value of a valid pgtype.Text.
func strVal(t pgtype.Text) string {
	if !t.Valid {
		return ""
	}
	return t.String
}

// ---------- Project adapter ----------

type pgProjectPort struct {
	q *sqlc.Queries
}

func (r *pgProjectPort) Create(ctx context.Context, input port.CreateProjectInput) (port.Project, error) {
	settings := input.Settings
	if len(settings) == 0 {
		settings = []byte("{}")
	}
	row, err := r.q.CreateProject(ctx, sqlc.CreateProjectParams{
		Slug:                input.Slug,
		Name:                input.Name,
		Description:         textPtrFromString(&input.Description),
		DeploymentThreshold: input.DeploymentThreshold,
		Settings:            settings,
	})
	if err != nil {
		return port.Project{}, err
	}
	return projectToPort(row), nil
}

func (r *pgProjectPort) List(ctx context.Context) ([]port.Project, error) {
	rows, err := r.q.ListProjects(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]port.Project, len(rows))
	for i, row := range rows {
		out[i] = projectToPort(row)
	}
	return out, nil
}

func (r *pgProjectPort) GetBySlug(ctx context.Context, slug string) (port.Project, error) {
	row, err := r.q.GetProjectBySlug(ctx, slug)
	if err != nil {
		return port.Project{}, err
	}
	return projectToPort(row), nil
}

func (r *pgProjectPort) GetByID(ctx context.Context, id string) (port.Project, error) {
	if _, err := parseID(id); err != nil {
		return port.Project{}, err
	}
	// No GetProjectByID query exists in sqlc; the watcher resolves project
	// config through its own query. Return not-found until a caller needs it.
	return port.Project{}, port.ErrNotFound
}

func projectToPort(p sqlc.Project) port.Project {
	return port.Project{
		ID:                     toUUID(p.ID),
		Slug:                   p.Slug,
		Name:                   p.Name,
		Description:            stringFromTextPtr(p.Description),
		DeploymentThreshold:    p.DeploymentThreshold,
		CveWatcherGate:         p.CveWatcherGate,
		CveWatcherEnabled:      p.CveWatcherEnabled,
		CveWatcherIntervalSecs: p.CveWatcherIntervalSeconds,
		CreatedAt:              p.CreatedAt.Time,
		UpdatedAt:              p.UpdatedAt.Time,
	}
}

// mappingErr adapts pgx no-rows to port.ErrNotFound.
func mappingErr(err error) error {
	if err == nil {
		return nil
	}
	if err.Error() == "no rows in result set" {
		return port.ErrNotFound
	}
	return err
}

var (
	_ = context.Background
	_ = port.Project{}
)
