package repo

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/xMinhx/specht/internal/db/sqlc"
	"github.com/xMinhx/specht/internal/port"
)

// pgAdminPort serves platform observability aggregates directly over sqlc.
type pgAdminPort struct{ q *sqlc.Queries }

func (r *pgAdminPort) Overview(ctx context.Context) (port.AdminOverview, error) {
	row, err := r.q.AdminOverview(ctx)
	if err != nil {
		return port.AdminOverview{}, mappingErr(err)
	}
	return port.AdminOverview{
		ProjectCount:          row.ProjectCount,
		UserCount:             row.UserCount,
		OpenFindingCount:      row.OpenFindingCount,
		ReportCount:           row.ReportCount,
		OldestSettledReportAt: timePtrFromTimestamptz(timestamptzFromAny(row.OldestSettledReportAt)),
	}, nil
}

// timestamptzFromAny decodes the nullable MIN() aggregate sqlc surfaces as
// interface{}: pgtype.Timestamptz when a settled report exists, nil
// otherwise. Anything unexpected decodes as absent, never as zero time.
func timestamptzFromAny(v any) pgtype.Timestamptz {
	switch t := v.(type) {
	case pgtype.Timestamptz:
		return t
	case time.Time:
		return pgtype.Timestamptz{Time: t, Valid: true}
	default:
		return pgtype.Timestamptz{}
	}
}
