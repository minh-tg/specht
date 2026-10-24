package usecase

import (
	"context"

	"github.com/minh-tg/specht/internal/domain"
	"github.com/minh-tg/specht/internal/port"
	"github.com/minh-tg/specht/internal/tracker"
)

type ingestTrackerEvents struct{ events []tracker.Event }

func (b *ingestTrackerEvents) Dispatch(_ context.Context, event tracker.Event) {
	b.events = append(b.events, event)
}

func (u *Usecases) ingestAtomically(ctx context.Context, project port.Project, input IngestReportInput, nr *domain.NormalizedReport, scopeHash, rawHash string) (*IngestReportOutput, error) {
	var report port.Report
	var result *IngestReportOutput
	var scoped *Usecases
	events := &ingestTrackerEvents{}
	err := u.deps.Stores.Ingest.Run(ctx, project.ID, func(stores *port.Stores) error {
		deps := u.deps
		deps.Stores = stores
		if deps.Tracker != nil {
			deps.Tracker = events
		}
		scoped = New(deps)
		scoped.ingestAtomic = true
		create := func(ctx context.Context, p port.Project, in IngestReportInput, parsed *domain.NormalizedReport, info reportContext, scope, hash string) (port.Report, error) {
			// The processing row survives rollback; every finding-related write
			// and the completed status below use the transaction-bound stores.
			var err error
			report, err = u.createReport(ctx, p, in, parsed, info, scope, hash)
			return report, err
		}
		var err error
		result, err = scoped.ingestParsedReport(ctx, project, input, nr, scopeHash, rawHash, create)
		return err
	})
	if err != nil {
		if report.ID != "" {
			// A commit can fail after the server has accepted it. Never turn a
			// completed report into failed in that ambiguous case; a retry can
			// replay the completed report instead.
			checkCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), failedReportTimeout)
			defer cancel()
			current, readErr := u.deps.Stores.Reports.GetByID(checkCtx, report.ID)
			if readErr == nil && current.Status == "processing" {
				reason := scoped.ingestFailure
				if reason == "" {
					reason = reportFailureCompletion
				}
				u.markReportFailed(checkCtx, input, report, reason, err)
			}
		}
		return nil, err
	}
	if !result.Replayed && u.deps.Tracker != nil {
		for _, event := range events.events {
			u.deps.Tracker.Dispatch(ctx, event)
		}
	}
	return result, nil
}
