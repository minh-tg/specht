package repo

import (
	"context"
	"time"

	"github.com/xMinhx/specht/internal/db/sqlc"
	"github.com/xMinhx/specht/internal/port"
)

// pgInventoryPort adapts InventoryStore over the existing repo.
type pgInventoryPort struct{ inner *pgInventoryRepo }

func (r *pgInventoryPort) UpsertReportPackages(ctx context.Context, reportID string, packages []port.PackageRef) error {
	rid, err := parseID(reportID)
	if err != nil {
		return err
	}
	params := make([]UpsertReportPackageParams, len(packages))
	for i, p := range packages {
		params[i] = UpsertReportPackageParams{
			PURL:         p.PURL,
			Ecosystem:    textPtrFromString(p.Ecosystem),
			Name:         textPtrFromString(p.Name),
			Version:      textPtrFromString(p.Version),
			ManifestPath: textPtrFromString(p.ManifestPath),
		}
	}
	return r.inner.UpsertReportPackages(ctx, rid, params)
}

func (r *pgInventoryPort) DistinctInventory(ctx context.Context, projectID string, since time.Duration) ([]port.InventoryPackage, error) {
	pid, err := parseID(projectID)
	if err != nil {
		return nil, err
	}
	rows, err := r.inner.DistinctInventory(ctx, pid, IntervalFromDuration(since))
	if err != nil {
		return nil, err
	}
	out := make([]port.InventoryPackage, len(rows))
	for i, row := range rows {
		out[i] = port.InventoryPackage{
			PURL:      row.Purl,
			Name:      strVal(row.Name),
			Version:   strVal(row.Version),
			Ecosystem: strVal(row.Ecosystem),
		}
	}
	return out, nil
}

func (r *pgInventoryPort) DeleteReportPackages(ctx context.Context, reportID string) error {
	rid, err := parseID(reportID)
	if err != nil {
		return err
	}
	return r.inner.DeleteReportPackages(ctx, rid)
}

// ---------- Stats ----------

type pgStatsPort struct{ inner StatsRepo }

func (r *pgStatsPort) GetProjectStats(ctx context.Context, projectID string) ([]port.SeverityStat, error) {
	pid, err := parseID(projectID)
	if err != nil {
		return nil, err
	}
	rows, err := r.inner.GetProjectStats(ctx, pid)
	if err != nil {
		return nil, err
	}
	out := make([]port.SeverityStat, len(rows))
	for i, row := range rows {
		out[i] = port.SeverityStat{
			Severity:      row.Severity,
			Count:         row.Count,
			BlockingCount: row.BlockingCount,
		}
	}
	return out, nil
}

func (r *pgStatsPort) GetProjectWaiverCount(ctx context.Context, projectID string) (int32, error) {
	pid, err := parseID(projectID)
	if err != nil {
		return 0, err
	}
	return r.inner.GetProjectWaiverCount(ctx, pid)
}

func (r *pgStatsPort) GetProjectReportCount(ctx context.Context, projectID string) (int32, error) {
	pid, err := parseID(projectID)
	if err != nil {
		return 0, err
	}
	return r.inner.GetProjectReportCount(ctx, pid)
}

func (r *pgStatsPort) GetProjectLatestReport(ctx context.Context, projectID string) (port.Report, error) {
	pid, err := parseID(projectID)
	if err != nil {
		return port.Report{}, err
	}
	row, err := r.inner.GetProjectLatestReport(ctx, pid)
	if err != nil {
		return port.Report{}, mappingErr(err)
	}
	return port.Report{
		ID:            toUUID(row.ID),
		ProjectID:     toUUID(row.ProjectID),
		ToolName:      row.ToolName,
		ToolVersion:   stringFromTextPtr(row.ToolVersion),
		ScanType:      row.ScanType,
		ScanTarget:    stringFromTextPtr(row.ScanTarget),
		Status:        row.Status,
		TotalFindings: int32PtrFromInt4(row.TotalFindings),
		Branch:        stringFromTextPtr(row.Branch),
		CommitSha:     stringFromTextPtr(row.CommitSha),
		CreatedAt:     row.CreatedAt.Time,
		CompletedAt:   timePtrFromTimestamptz(row.CompletedAt),
	}, nil
}

// ---------- Watcher ----------

type pgWatcherPort struct{ inner WatcherRepo }

func (r *pgWatcherPort) GetState(ctx context.Context) (port.WatcherState, error) {
	row, err := r.inner.GetState(ctx)
	if err != nil {
		return port.WatcherState{}, mappingErr(err)
	}
	return watcherStateToPort(row), nil
}

func (r *pgWatcherPort) UpdateState(ctx context.Context, ts time.Time) error {
	return r.inner.UpdateState(ctx, ts)
}

func (r *pgWatcherPort) RecordAttempt(ctx context.Context, ts time.Time) error {
	return r.inner.RecordAttempt(ctx, ts)
}

func (r *pgWatcherPort) RecordFailure(ctx context.Context, errText string, ts time.Time) error {
	return r.inner.RecordFailure(ctx, errText, ts)
}

func (r *pgWatcherPort) ResetFailure(ctx context.Context) error {
	return r.inner.ResetFailure(ctx)
}

func (r *pgWatcherPort) GetProjectConfig(ctx context.Context, projectID string) (port.Project, error) {
	pid, err := parseID(projectID)
	if err != nil {
		return port.Project{}, err
	}
	row, err := r.inner.GetProjectConfig(ctx, pid)
	if err != nil {
		return port.Project{}, mappingErr(err)
	}
	return port.Project{
		ID:                     toUUID(row.ID),
		Slug:                   row.Slug,
		Name:                   row.Name,
		CveWatcherEnabled:      row.CveWatcherEnabled,
		CveWatcherIntervalSecs: row.CveWatcherIntervalSeconds,
	}, nil
}

func (r *pgWatcherPort) GetProjectState(ctx context.Context, projectID string) (port.WatcherProjectState, error) {
	pid, err := parseID(projectID)
	if err != nil {
		return port.WatcherProjectState{}, err
	}
	row, err := r.inner.GetProjectState(ctx, pid)
	if err != nil {
		return port.WatcherProjectState{}, mappingErr(err)
	}
	return port.WatcherProjectState{
		ProjectID:            toUUID(row.ProjectID),
		LastSuccessfulPollAt: timePtrFromTimestamptz(row.LastSuccessfulPollAt),
	}, nil
}

func (r *pgWatcherPort) UpsertProjectState(ctx context.Context, projectID string, ts time.Time) error {
	pid, err := parseID(projectID)
	if err != nil {
		return err
	}
	return r.inner.UpsertProjectState(ctx, pid, ts)
}

func watcherStateToPort(s sqlc.WatcherState) port.WatcherState {
	return port.WatcherState{
		LastSuccessfulPollAt: timePtrFromTimestamptz(s.LastSuccessfulPollAt),
		LastPollAttemptAt:    timePtrFromTimestamptz(s.LastPollAttemptAt),
		LastError:            stringFromTextPtr(s.LastError),
		ConsecutiveFailures:  s.ConsecutiveFailures,
	}
}
