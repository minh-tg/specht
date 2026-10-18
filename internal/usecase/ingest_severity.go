package usecase

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/minh-tg/specht/internal/port"
)

// severityValue is a severity with its rank. A finding row and a scope row
// both store this pair.
type severityValue struct {
	text string
	rank int16
}

// higherSeverity returns the more severe of a and b. A tie keeps a.
func higherSeverity(a, b severityValue) severityValue {
	if b.rank > a.rank {
		return b
	}
	return a
}

// scopeSeverities indexes the per-scope severities of the known findings by
// finding ID. prefetchScopeSeverities fills it once per ingest.
type scopeSeverities map[string][]port.FindingScopeSeverity

// prefetchScopeSeverities loads the per-scope severities of every known
// finding in one query (Phase 1).
func (u *Usecases) prefetchScopeSeverities(ctx context.Context, st *ingestFindingsState) error {
	st.scopeSev = scopeSeverities{}
	if len(st.knownIDs) == 0 {
		return nil
	}
	rows, err := u.deps.Stores.Findings.ListScopeSeverities(ctx, st.knownIDs)
	if err != nil {
		slog.Error("pre-fetch scope severities failed", "scanner", st.input.Scanner, "error", err)
		return fmt.Errorf("scanner %s: pre-fetch scope severities: %w", st.input.Scanner, err)
	}
	for _, r := range rows {
		st.scopeSev[r.FindingID] = append(st.scopeSev[r.FindingID], r)
	}
	return nil
}

// ownScopeSeverity returns the severity this ingest's scope last reported for
// the finding, and false when the scope has not reported it before.
func (st *ingestFindingsState) ownScopeSeverity(findingID string) (port.FindingScopeSeverity, bool) {
	for _, s := range st.scopeSev[findingID] {
		if s.ScopeHash == st.scopeHash {
			return s, true
		}
	}
	return port.FindingScopeSeverity{}, false
}

// projectSeverity returns the severity the finding row holds after this scan:
// the highest of the scan's own severity and what every other scope last
// reported. A scan writes only its own scope, so a lower value here cannot hide
// a higher one that another branch or scanner reported.
func (st *ingestFindingsState) projectSeverity(findingID string, incoming severityValue) severityValue {
	project := incoming
	for _, s := range st.scopeSev[findingID] {
		if s.ScopeHash == st.scopeHash {
			continue
		}
		project = higherSeverity(project, severityValue{text: s.Severity, rank: s.SeverityRank})
	}
	return project
}

// recordScopeSeverity stores the severity this scan's scope reported. It writes
// one severity_changed event when that scope's value moved or the project-wide
// value moved. A finding seen for the first time has nothing to compare, so it
// writes no event.
//
// A report can name the same finding more than once. Only the finding's last
// occurrence writes the event, so the report leaves one event per finding. Its
// old value is this scope's value before the report, its previous report or the
// project-wide value when the scope had not reported before, and its new value
// is the last severity the report sets. The changes document carries the
// project-wide value before and after the scan.
func (u *Usecases) recordScopeSeverity(ctx context.Context, st *ingestFindingsState, upserted, prior port.Finding, exists, final bool, incoming, project severityValue) error {
	previous, hadScope := st.ownScopeSeverity(upserted.ID)
	row := port.FindingScopeSeverityInput{
		FindingID:    upserted.ID,
		ScopeHash:    st.scopeHash,
		Severity:     incoming.text,
		SeverityRank: incoming.rank,
		ReportID:     st.report.ID,
		ObservedAt:   st.nowTime,
	}
	// A batch-capable store takes the row with the ingest's other batched
	// writes, in one statement at the end. The comparison above reads only
	// the prefetched rows, so the deferred write does not change the outcome.
	if st.batchStore != nil {
		st.scopeRows = append(st.scopeRows, row)
	} else if err := u.deps.Stores.Findings.UpsertScopeSeverity(ctx, row); err != nil {
		slog.Error("record scope severity failed", "scanner", st.input.Scanner, "finding", upserted.ID, "error", err)
		return fmt.Errorf("scanner %s: record scope severity for finding %q: %w", st.input.Scanner, upserted.ID, err)
	}
	if !exists || !final {
		return nil
	}

	before := severityValue{text: prior.CurrentSeverity, rank: prior.CurrentSeverityRank}
	if hadScope {
		before = severityValue{text: previous.Severity, rank: previous.SeverityRank}
	}
	projectMoved := prior.CurrentSeverityRank != project.rank
	if before.rank == incoming.rank && !projectMoved {
		return nil
	}

	changes := mustMarshal(map[string]any{
		"scanner":                 st.input.Scanner,
		"scope_hash":              st.scopeHash,
		"report_id":               st.report.ID,
		"project_severity_before": prior.CurrentSeverity,
		"project_severity_after":  project.text,
	})
	if _, err := u.deps.Stores.Findings.CreateEvent(ctx, port.FindingEventInput{
		FindingID: upserted.ID,
		EventType: "severity_changed",
		OldValue:  strPtr(before.text),
		NewValue:  strPtr(incoming.text),
		Changes:   changes,
	}); err != nil {
		slog.Error("log severity_changed event failed", "scanner", st.input.Scanner, "finding", upserted.ID, "error", err)
		return fmt.Errorf("scanner %s: log severity_changed event: %w", st.input.Scanner, err)
	}
	return nil
}
