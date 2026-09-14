package usecase

import (
	"context"
	"fmt"
	"time"
)

// maxRetentionDays bounds retention windows: beyond ten years a cutoff is
// certainly a caller bug, not a policy.
const maxRetentionDays = 3650

// RetentionPreview counts settled reports a purge would delete, without
// deleting anything.
type RetentionPreview struct {
	OlderThanDays int       `json:"older_than_days"`
	Cutoff        time.Time `json:"cutoff"`
	StaleReports  int64     `json:"stale_reports"`
}

// RetentionResult reports what a purge deleted.
type RetentionResult struct {
	OlderThanDays    int       `json:"older_than_days"`
	Cutoff           time.Time `json:"cutoff"`
	DeletedReports   int64     `json:"deleted_reports"`
	DeletedReportIDs []string  `json:"deleted_report_ids,omitempty"`
}

// AdminStatus is the platform observability snapshot for admins.
type AdminStatus struct {
	Projects              int64      `json:"projects"`
	Users                 int64      `json:"users"`
	OpenFindings          int64      `json:"open_findings"`
	Reports               int64      `json:"reports"`
	OldestSettledReportAt *time.Time `json:"oldest_settled_report_at"`
}

// validateRetentionDays rejects non-positive and absurd windows.
func validateRetentionDays(days int) error {
	if days <= 0 {
		return fmt.Errorf("older_than_days must be positive")
	}
	if days > maxRetentionDays {
		return fmt.Errorf("older_than_days must not exceed %d", maxRetentionDays)
	}
	return nil
}

// PreviewRetention counts settled (completed/failed) reports older than the
// window. Processing reports are never counted.
func (u *Usecases) PreviewRetention(ctx context.Context, olderThanDays int) (*RetentionPreview, error) {
	if err := validateRetentionDays(olderThanDays); err != nil {
		return nil, err
	}
	cutoff := now().AddDate(0, 0, -olderThanDays)
	count, err := u.deps.Stores.Reports.CountStaleReports(ctx, cutoff)
	if err != nil {
		return nil, fmt.Errorf("count stale reports: %w", err)
	}
	return &RetentionPreview{OlderThanDays: olderThanDays, Cutoff: cutoff, StaleReports: count}, nil
}

// PurgeRetention deletes settled reports older than the window.
// Occurrences, watcher rows, and inventory cascade; finding attribution
// nulls; findings themselves survive.
func (u *Usecases) PurgeRetention(ctx context.Context, olderThanDays int) (*RetentionResult, error) {
	if err := validateRetentionDays(olderThanDays); err != nil {
		return nil, err
	}
	cutoff := now().AddDate(0, 0, -olderThanDays)
	ids, err := u.deps.Stores.Reports.DeleteStaleReports(ctx, cutoff)
	if err != nil {
		return nil, fmt.Errorf("purge stale reports: %w", err)
	}
	return &RetentionResult{OlderThanDays: olderThanDays, Cutoff: cutoff, DeletedReports: int64(len(ids)), DeletedReportIDs: ids}, nil
}

// GetAdminStatus returns the platform observability snapshot. Callers gate
// it to global admins at the route layer.
func (u *Usecases) GetAdminStatus(ctx context.Context) (*AdminStatus, error) {
	overview, err := u.deps.Stores.Admin.Overview(ctx)
	if err != nil {
		return nil, fmt.Errorf("admin overview: %w", err)
	}
	return &AdminStatus{
		Projects:              overview.ProjectCount,
		Users:                 overview.UserCount,
		OpenFindings:          overview.OpenFindingCount,
		Reports:               overview.ReportCount,
		OldestSettledReportAt: overview.OldestSettledReportAt,
	}, nil
}
