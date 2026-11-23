package repo

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/minh-tg/specht/internal/db/sqlc"
	"github.com/minh-tg/specht/internal/port"
)

type pgNeedsYouPort struct{ q *sqlc.Queries }

func parseIDs(ids []string) ([]pgtype.UUID, error) {
	out := make([]pgtype.UUID, 0, len(ids))
	for _, id := range ids {
		parsed, err := parseID(id)
		if err != nil {
			return nil, err
		}
		out = append(out, parsed)
	}
	return out, nil
}

func timestamptz(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: t, Valid: true}
}

func (r *pgNeedsYouPort) ListManagedProjectIDs(ctx context.Context, userID string) ([]string, error) {
	uid, err := parseID(userID)
	if err != nil {
		return nil, err
	}
	rows, err := r.q.ListManagedProjectIDs(ctx, uid)
	if err != nil {
		return nil, mappingErr(err)
	}
	out := make([]string, len(rows))
	for i, row := range rows {
		out[i] = toUUID(row)
	}
	return out, nil
}

func (r *pgNeedsYouPort) ListPendingWaiverRequests(ctx context.Context, projectIDs []string, limit int32) ([]port.NeedsYouWaiver, error) {
	ids, err := parseIDs(projectIDs)
	if err != nil {
		return nil, err
	}
	rows, err := r.q.ListPendingWaiverRequests(ctx, sqlc.ListPendingWaiverRequestsParams{ProjectIds: ids, MaxRows: limit})
	if err != nil {
		return nil, mappingErr(err)
	}
	out := make([]port.NeedsYouWaiver, len(rows))
	for i, row := range rows {
		out[i] = port.NeedsYouWaiver{
			ID: toUUID(row.ID), ProjectID: toUUID(row.ProjectID), ProjectSlug: row.ProjectSlug,
			ProjectName: row.ProjectName, Name: row.Name, Reason: row.Reason,
			RequestedBy: optionalUUID(row.RequestedBy), Status: "pending", At: row.AskedAt.Time,
		}
	}
	return out, nil
}

func (r *pgNeedsYouPort) ListDecidedWaiverRequests(ctx context.Context, userID string, projectIDs []string, since time.Time, limit int32) ([]port.NeedsYouWaiver, error) {
	uid, err := parseID(userID)
	if err != nil {
		return nil, err
	}
	ids, err := parseIDs(projectIDs)
	if err != nil {
		return nil, err
	}
	rows, err := r.q.ListDecidedWaiverRequests(ctx, sqlc.ListDecidedWaiverRequestsParams{
		UserID: uid, Since: timestamptz(since), ProjectIds: ids, MaxRows: limit,
	})
	if err != nil {
		return nil, mappingErr(err)
	}
	out := make([]port.NeedsYouWaiver, len(rows))
	for i, row := range rows {
		out[i] = port.NeedsYouWaiver{
			ID: toUUID(row.ID), ProjectID: toUUID(row.ProjectID), ProjectSlug: row.ProjectSlug,
			ProjectName: row.ProjectName, Name: row.Name, RequestedBy: userID, Status: row.Status,
			DecisionNote: row.DecisionNote, DecisionReason: row.DecisionReason.String, At: row.DecidedAt.Time,
		}
	}
	return out, nil
}

func (r *pgNeedsYouPort) ListWaiversEnding(ctx context.Context, projectIDs []string, after, until time.Time, limit int32) ([]port.NeedsYouWaiver, error) {
	ids, err := parseIDs(projectIDs)
	if err != nil {
		return nil, err
	}
	rows, err := r.q.ListWaiversEnding(ctx, sqlc.ListWaiversEndingParams{
		After: timestamptz(after), Until: timestamptz(until), ProjectIds: ids, MaxRows: limit,
	})
	if err != nil {
		return nil, mappingErr(err)
	}
	out := make([]port.NeedsYouWaiver, len(rows))
	for i, row := range rows {
		out[i] = port.NeedsYouWaiver{
			ID: toUUID(row.ID), ProjectID: toUUID(row.ProjectID), ProjectSlug: row.ProjectSlug,
			ProjectName: row.ProjectName, Name: row.Name, Status: "approved", At: row.EndsAt.Time,
		}
	}
	return out, nil
}

func (r *pgNeedsYouPort) ListOpenFindingsAssignedTo(ctx context.Context, userID string, projectIDs []string, limit int32) ([]port.NeedsYouFinding, error) {
	uid, err := parseID(userID)
	if err != nil {
		return nil, err
	}
	ids, err := parseIDs(projectIDs)
	if err != nil {
		return nil, err
	}
	rows, err := r.q.ListOpenFindingsAssignedTo(ctx, sqlc.ListOpenFindingsAssignedToParams{UserID: uid, ProjectIds: ids, MaxRows: limit})
	if err != nil {
		return nil, mappingErr(err)
	}
	out := make([]port.NeedsYouFinding, len(rows))
	for i, row := range rows {
		out[i] = port.NeedsYouFinding{
			ID: toUUID(row.ID), ProjectID: toUUID(row.ProjectID), ProjectSlug: row.ProjectSlug,
			ProjectName: row.ProjectName, Title: row.CurrentTitle, Severity: row.CurrentSeverity,
			LastSeenAt: row.LastSeenAt.Time,
		}
	}
	return out, nil
}

func (r *pgNeedsYouPort) CountOpenFindingsAssignedTo(ctx context.Context, userID string, projectIDs []string) (int64, error) {
	uid, err := parseID(userID)
	if err != nil {
		return 0, err
	}
	ids, err := parseIDs(projectIDs)
	if err != nil {
		return 0, err
	}
	n, err := r.q.CountOpenFindingsAssignedTo(ctx, sqlc.CountOpenFindingsAssignedToParams{UserID: uid, ProjectIds: ids})
	return n, mappingErr(err)
}
