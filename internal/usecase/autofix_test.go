package usecase

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/domain"
	"github.com/minh-tg/specht/internal/port"
	"github.com/minh-tg/specht/internal/scanner"
)

// autofixHarness mirrors the unknown-scan regression setup with a parser
// that vouches for completeness, so the ingest reaches the ADR-018
// auto-fix writer.
func autofixHarness(t *testing.T, completeness domain.ScanCompleteness) (*Usecases, *mockFindingRepo, *mockReportRepo) {
	t.Helper()
	pr, rr, fr := makeTestRepos()

	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return makeProject(true), nil
	}
	rr.createFn = func(ctx context.Context, arg port.CreateReportInput) (port.Report, error) {
		return makeReport(), nil
	}
	rr.updateStatusFn = func(ctx context.Context, id, projectID string, status string, totalFindings int32, errorMsg *string) (port.Report, error) {
		return makeReport(), nil
	}
	fr.getByFingerprintFn = func(ctx context.Context, projectID, findingKind, fingerprint string) (port.Finding, error) {
		return port.Finding{}, port.ErrNotFound
	}
	fr.upsertFn = func(ctx context.Context, in port.UpsertFindingInput) (port.Finding, error) {
		return port.Finding{
			ID: "find-1", ProjectID: in.ProjectID, FindingKind: in.FindingKind,
			Fingerprint: in.Fingerprint, CurrentTitle: in.Title, CurrentSeverity: in.Severity,
			CurrentSeverityRank: in.SeverityRank, State: "open", AnalysisState: "unanalyzed",
			GateEffect: "block", FirstSeenAt: in.FirstSeen, LastSeenAt: in.LastSeen,
		}, nil
	}
	fr.createOccurrenceFn = func(ctx context.Context, arg port.OccurrenceInput) (port.Occurrence, error) {
		return port.Occurrence{ID: "occ-1", FindingID: arg.FindingID}, nil
	}
	fr.upsertDimensionFn = func(ctx context.Context, arg port.DimensionInput) error { return nil }
	fr.listGateCandidatesFn = func(ctx context.Context, projectID string, minSeverityRank int16) ([]port.GateCandidate, error) {
		return nil, nil
	}

	reg := scanner.NewRegistry()
	require.NoError(t, reg.Register(&mockScanner{
		name: "trivy",
		parseFn: func(ctx context.Context, input []byte) (*domain.NormalizedReport, error) {
			return &domain.NormalizedReport{
				ScanType:     domain.ScanTypeImage,
				Completeness: completeness,
				Target:       &domain.TargetInfo{Kind: "container", Identifier: "img:latest"},
				Findings: []domain.NormalizedFinding{{
					Fingerprint: "fp-new", FindingKind: "sca",
					Title: "CVE-new", Severity: domain.SeverityHigh,
				}},
				ScanScope: &domain.ScanScope{},
			}, nil
		},
	}))

	uc := New(Deps{
		Stores: &port.Stores{
			Projects: pr, Reports: rr, Findings: fr, Waivers: &mockWaiverRepo{},
			Targets: stubTargetRepo(), Artifacts: stubArtifactRepo(),
			Environments: &mockEnvironmentRepo{},
		},
		Registry: reg,
	})
	return uc, fr, rr
}

// TestIngestReport_AutoFixClosesAbsentFindings pins the writer contract:
// a full scan whose parser vouches completeness "complete" invokes the
// scoped store writer with the report's scope hash and records a
// state_changed event naming the source report for every closed finding.
func TestIngestReport_AutoFixClosesAbsentFindings(t *testing.T) {
	uc, fr, _ := autofixHarness(t, domain.CompletenessComplete)

	type writerCall struct {
		projectID, scopeHash, reportID string
	}
	var call *writerCall
	fr.markAbsentFixedFn = func(ctx context.Context, projectID, scopeHash, reportID string) ([]port.Finding, error) {
		call = &writerCall{projectID, scopeHash, reportID}
		return []port.Finding{{
			ID: "find-fixed", ProjectID: projectID, FindingKind: "sca",
			Fingerprint: "fp-old", CurrentTitle: "CVE-old",
			CurrentSeverity: "high", CurrentSeverityRank: 30,
			State: "fixed", AnalysisState: "unanalyzed", GateEffect: "block",
		}}, nil
	}
	var events []port.FindingEventInput
	fr.createEventFn = func(ctx context.Context, input port.FindingEventInput) (port.FindingEvent, error) {
		events = append(events, input)
		return port.FindingEvent{FindingID: input.FindingID, EventType: input.EventType}, nil
	}

	out, err := uc.IngestReport(context.Background(), IngestReportInput{
		ProjectSlug: "my-app",
		Scanner:     "trivy",
		RawData:     json.RawMessage(`{"test": true}`),
	})
	require.NoError(t, err)

	require.NotNil(t, call, "a complete full scan must invoke the auto-fix writer")
	assert.Equal(t, out.ReportID, call.reportID, "absence is judged against this report")
	assert.Len(t, call.scopeHash, 64, "scope hash is the hex digest of the scan-scope material")
	assert.Equal(t, makeProject(true).ID, call.projectID)

	require.Len(t, events, 1, "one state_changed event per closed finding")
	ev := events[0]
	assert.Equal(t, "find-fixed", ev.FindingID)
	assert.Equal(t, "state_changed", ev.EventType)
	require.NotNil(t, ev.NewValue)
	assert.Equal(t, "fixed", *ev.NewValue)
	var changes map[string]any
	require.NoError(t, json.Unmarshal(ev.Changes, &changes))
	assert.Equal(t, out.ReportID, changes["report_id"])
	assert.Equal(t, "trivy", changes["scanner"])
}

// TestIngestReport_AutoFixSkipsUnknownCompleteness pins the parser-vouch
// gate: a report normalized to completeness "unknown" never reaches the
// writer, so an unseen fingerprint stays open.
func TestIngestReport_AutoFixSkipsUnknownCompleteness(t *testing.T) {
	uc, fr, _ := autofixHarness(t, domain.CompletenessUnknown)
	fr.markAbsentFixedFn = func(ctx context.Context, projectID, scopeHash, reportID string) ([]port.Finding, error) {
		t.Error("writer must not run for an unknown-completeness scan")
		return nil, nil
	}

	out, err := uc.IngestReport(context.Background(), IngestReportInput{
		ProjectSlug: "my-app",
		Scanner:     "trivy",
		RawData:     json.RawMessage(`{"test": true}`),
	})
	require.NoError(t, err)
	assert.Equal(t, 1, out.TotalFindings)
}

// TestAutoFixAbsentFindings_SkipsIncrementalScans pins the mode gate:
// absence in an incremental scan proves nothing, so even a
// completeness-complete parser never reaches the writer.
func TestAutoFixAbsentFindings_SkipsIncrementalScans(t *testing.T) {
	_, fr, _ := autofixHarness(t, domain.CompletenessComplete)
	fr.markAbsentFixedFn = func(ctx context.Context, projectID, scopeHash, reportID string) ([]port.Finding, error) {
		t.Error("writer must not run for an incremental scan")
		return nil, nil
	}

	uc := New(Deps{Stores: &port.Stores{Findings: fr}})
	err := uc.autoFixAbsentFindings(context.Background(), makeProject(true),
		IngestReportInput{ProjectSlug: "my-app", Scanner: "trivy", ScanMode: ScanModeIncremental},
		port.Report{ID: "rep-1"},
		&domain.NormalizedReport{Completeness: domain.CompletenessComplete},
		reportContext{})
	require.NoError(t, err)
}

// TestIngestReport_AutoFixStoreErrorFailsIngest: the writer runs inside
// the ingest transaction's logical flow — a store failure marks the report
// failed and surfaces, instead of silently skipping the closure.
func TestIngestReport_AutoFixStoreErrorFailsIngest(t *testing.T) {
	uc, fr, rr := autofixHarness(t, domain.CompletenessComplete)
	fr.markAbsentFixedFn = func(ctx context.Context, projectID, scopeHash, reportID string) ([]port.Finding, error) {
		return nil, assert.AnError
	}
	var failedStatus string
	rr.updateStatusFn = func(ctx context.Context, id, projectID string, status string, totalFindings int32, errorMsg *string) (port.Report, error) {
		failedStatus = status
		return makeReport(), nil
	}

	_, err := uc.IngestReport(context.Background(), IngestReportInput{
		ProjectSlug: "my-app",
		Scanner:     "trivy",
		RawData:     json.RawMessage(`{"test": true}`),
	})
	require.Error(t, err)
	assert.ErrorContains(t, err, "auto-fix absent findings")
	assert.Equal(t, "failed", failedStatus)
}
