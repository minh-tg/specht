package usecase

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/domain"
	"github.com/minh-tg/specht/internal/port"
	"github.com/minh-tg/specht/internal/scanner"
)

type repeatCounts struct {
	analysisUpdates int
	dimensionReads  int
	events          map[string]int
}

// ingestRepeated ingests a report that names one triaged finding entries
// times; fixOn chooses which entries carry a fixed version.
func ingestRepeated(t *testing.T, entries int, severity domain.Severity, fixOn func(i int) bool) repeatCounts {
	t.Helper()
	uc, fr, _ := autofixHarness(t, domain.CompletenessUnknown)
	known := port.Finding{
		ID: "f-triaged", ProjectID: makeProject(true).ID, FindingKind: "sast", Fingerprint: "sast:r:a.go",
		State: "open", AnalysisState: "accepted_risk", GateEffect: "ignore",
		CurrentSeverity: "medium", CurrentSeverityRank: 2,
	}
	fr.listFindingsByFingerprintsFn = func(ctx context.Context, projectID, kind string, fps []string) ([]port.Finding, error) {
		return []port.Finding{known}, nil
	}
	fr.upsertFn = func(ctx context.Context, in port.UpsertFindingInput) (port.Finding, error) {
		row := known
		row.CurrentSeverity, row.CurrentSeverityRank = in.Severity, in.SeverityRank
		return row, nil
	}
	counts := repeatCounts{events: map[string]int{}}
	fr.updateAnalysisFn = func(ctx context.Context, in port.UpdateAnalysisInput) (port.Finding, error) {
		counts.analysisUpdates++
		return known, nil
	}
	fr.createEventFn = func(ctx context.Context, in port.FindingEventInput) (port.FindingEvent, error) {
		counts.events[in.EventType]++
		return port.FindingEvent{}, nil
	}
	fr.hasDimensionFn = func(ctx context.Context, id, key string) (bool, error) {
		counts.dimensionReads++
		return false, nil
	}
	findings := make([]domain.NormalizedFinding, entries)
	for i := range findings {
		findings[i] = domain.NormalizedFinding{
			Fingerprint: "sast:r:a.go", FindingKind: "sast", Title: fmt.Sprintf("entry %d", i), Severity: severity,
		}
		if fixOn(i) {
			findings[i].Dimensions = []domain.Dimension{{Key: domain.DimFixedVersion, Value: "1.2.3"}}
		}
	}
	require.NoError(t, uc.deps.Registry.(*scanner.Registry).Register(&mockScanner{
		name: "repeat",
		parseFn: func(context.Context, []byte) (*domain.NormalizedReport, error) {
			return &domain.NormalizedReport{
				ScanType: domain.ScanTypeRepository, Findings: findings, ScanScope: &domain.ScanScope{},
				Target: &domain.TargetInfo{Kind: "repository", Identifier: "r"},
			}, nil
		},
	}))
	_, err := uc.IngestReport(context.Background(), IngestReportInput{
		ProjectSlug: "my-app", Scanner: "repeat", RawData: json.RawMessage(`{"a":1}`),
	})
	require.NoError(t, err)
	return counts
}

// A report that names one triaged finding many times judges its material
// change once: one event, one review_required write and one read of the fix
// dimension, not one per entry.
func TestIngestReport_AFindingNamedManyTimesJudgesItsMaterialChangeOnce(t *testing.T) {
	got := ingestRepeated(t, 50, domain.SeverityCritical, func(int) bool { return true })
	assert.Equal(t, 1, got.events["reopened_severity_change"])
	assert.Equal(t, 1, got.analysisUpdates)
	assert.Equal(t, 1, got.dimensionReads)
}

// A fixed version named only by an earlier entry still counts: the finding
// reopens once because a fix became available, judged against the dimension
// as it was before the report.
func TestIngestReport_AFixNamedByAnEarlierEntryStillReopensOnce(t *testing.T) {
	got := ingestRepeated(t, 5, domain.SeverityMedium, func(i int) bool { return i == 1 })
	assert.Equal(t, 1, got.events["reopened_fix_available"])
	assert.Equal(t, 1, got.analysisUpdates)
	assert.Equal(t, 1, got.dimensionReads)
}
