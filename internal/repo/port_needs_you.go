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

func (r *pgNeedsYouPort) ListProjectsWithOwnPendingRequests(ctx context.Context, userID string, projectIDs []string) ([]string, error) {
	uid, err := parseID(userID)
	if err != nil {
		return nil, err
	}
	ids, err := parseIDs(projectIDs)
	if err != nil {
		return nil, err
	}
	rows, err := r.q.ListProjectsWithOwnPendingRequests(ctx, sqlc.ListProjectsWithOwnPendingRequestsParams{UserID: uid, ProjectIds: ids})
	if err != nil {
		return nil, mappingErr(err)
	}
	out := make([]string, len(rows))
	for i, row := range rows {
		out[i] = toUUID(row)
	}
	return out, nil
}

func (r *pgNeedsYouPort) ListPendingWaiverRequests(ctx context.Context, callerID string, projectIDs, hideOwnIn []string, limit int32) (port.NeedsYouWaivers, error) {
	caller, err := parseID(callerID)
	if err != nil {
		return port.NeedsYouWaivers{}, err
	}
	ids, err := parseIDs(projectIDs)
	if err != nil {
		return port.NeedsYouWaivers{}, err
	}
	// parseIDs never returns nil: a NULL array would make "<> ALL" unknown and drop every one of
	// the caller's own requests.
	hide, err := parseIDs(hideOwnIn)
	if err != nil {
		return port.NeedsYouWaivers{}, err
	}
	rows, err := r.q.ListPendingWaiverRequests(ctx, sqlc.ListPendingWaiverRequestsParams{
		ProjectIds: ids, CallerID: caller, HideOwnIn: hide, MaxRows: limit,
	})
	if err != nil {
		return port.NeedsYouWaivers{}, mappingErr(err)
	}
	out := port.NeedsYouWaivers{Items: make([]port.NeedsYouWaiver, len(rows))}
	for i, row := range rows {
		out.Items[i] = port.NeedsYouWaiver{
			ID: toUUID(row.ID), ProjectID: toUUID(row.ProjectID), ProjectSlug: row.ProjectSlug,
			ProjectName: row.ProjectName, Name: row.Name, Reason: row.Reason,
			RequestedBy: optionalUUID(row.RequestedBy), Status: "pending", At: row.AskedAt.Time,
		}
		out.Total = int(row.Total)
	}
	return out, nil
}

func (r *pgNeedsYouPort) ListDecidedWaiverRequests(ctx context.Context, userID string, projectIDs []string, since, freshSince time.Time, limit int32) (port.NeedsYouWaivers, error) {
	uid, err := parseID(userID)
	if err != nil {
		return port.NeedsYouWaivers{}, err
	}
	ids, err := parseIDs(projectIDs)
	if err != nil {
		return port.NeedsYouWaivers{}, err
	}
	rows, err := r.q.ListDecidedWaiverRequests(ctx, sqlc.ListDecidedWaiverRequestsParams{
		UserID: uid, Since: timestamptz(since), FreshSince: timestamptz(freshSince), ProjectIds: ids, MaxRows: limit,
	})
	if err != nil {
		return port.NeedsYouWaivers{}, mappingErr(err)
	}
	out := port.NeedsYouWaivers{Items: make([]port.NeedsYouWaiver, len(rows))}
	for i, row := range rows {
		out.Items[i] = port.NeedsYouWaiver{
			ID: toUUID(row.ID), ProjectID: toUUID(row.ProjectID), ProjectSlug: row.ProjectSlug,
			ProjectName: row.ProjectName, Name: row.Name, RequestedBy: userID, Status: row.Status,
			DecisionNote: row.DecisionNote, DecisionReason: row.DecisionReason.String,
			Enabled: row.Enabled, ExpiresAt: timePtrFromTimestamptz(row.ExpiresAt), At: row.DecidedAt.Time,
		}
		out.Total, out.Fresh = int(row.Total), int(row.Fresh)
	}
	return out, nil
}

func (r *pgNeedsYouPort) ListWaiversEnding(ctx context.Context, projectIDs []string, after, until time.Time, limit int32) (port.NeedsYouWaivers, error) {
	ids, err := parseIDs(projectIDs)
	if err != nil {
		return port.NeedsYouWaivers{}, err
	}
	rows, err := r.q.ListWaiversEnding(ctx, sqlc.ListWaiversEndingParams{
		After: timestamptz(after), Until: timestamptz(until), ProjectIds: ids, MaxRows: limit,
	})
	if err != nil {
		return port.NeedsYouWaivers{}, mappingErr(err)
	}
	out := port.NeedsYouWaivers{Items: make([]port.NeedsYouWaiver, len(rows))}
	for i, row := range rows {
		out.Items[i] = port.NeedsYouWaiver{
			ID: toUUID(row.ID), ProjectID: toUUID(row.ProjectID), ProjectSlug: row.ProjectSlug,
			ProjectName: row.ProjectName, Name: row.Name, Status: "approved", At: row.EndsAt.Time,
		}
		out.Total = int(row.Total)
	}
	return out, nil
}

func (r *pgNeedsYouPort) ListOpenFindingsAssignedTo(ctx context.Context, userID string, projectIDs []string, limit int32) (port.NeedsYouFindings, error) {
	uid, err := parseID(userID)
	if err != nil {
		return port.NeedsYouFindings{}, err
	}
	ids, err := parseIDs(projectIDs)
	if err != nil {
		return port.NeedsYouFindings{}, err
	}
	rows, err := r.q.ListOpenFindingsAssignedTo(ctx, sqlc.ListOpenFindingsAssignedToParams{UserID: uid, ProjectIds: ids, MaxRows: limit})
	if err != nil {
		return port.NeedsYouFindings{}, mappingErr(err)
	}
	out := port.NeedsYouFindings{Items: make([]port.NeedsYouFinding, len(rows))}
	for i, row := range rows {
		out.Items[i] = port.NeedsYouFinding{
			ID: toUUID(row.ID), ProjectID: toUUID(row.ProjectID), ProjectSlug: row.ProjectSlug,
			ProjectName: row.ProjectName, Title: row.CurrentTitle, Severity: row.CurrentSeverity,
			LastSeenAt: row.LastSeenAt.Time,
		}
		out.Total = int(row.Total)
	}
	return out, nil
}
