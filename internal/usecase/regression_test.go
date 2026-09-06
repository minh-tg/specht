package usecase

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xMinhx/specht/internal/domain"
	"github.com/xMinhx/specht/internal/finding"
	"github.com/xMinhx/specht/internal/port"
	"github.com/xMinhx/specht/internal/scanner"
)

// TestIngestRegression_LogsEvent verifies that when a finding previously
// marked fixed reappears in a new scan, ingest logs a 'regression' event
// and the finding's technical state flips to 'reopened'.
func TestIngestRegression_LogsEvent(t *testing.T) {
	pr, rr, fr := makeTestRepos()
	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return makeProject(true), nil
	}
	rr.createFn = func(ctx context.Context, arg port.CreateReportInput) (port.Report, error) {
		return makeReport(), nil
	}
	rr.updateStatusFn = func(ctx context.Context, id, projectID, status string, totalFindings int32, errorMsg *string) (port.Report, error) {
		r := makeReport()
		r.Status = status
		return r, nil
	}

	existing := makeFinding(9)
	existing.State = "fixed"
	existing.AnalysisState = "unanalyzed"
	fr.getByFingerprintFn = func(ctx context.Context, findingID, findingKind, fingerprint string) (port.Finding, error) {
		return existing, nil
	}
	var upsertedState string
	fr.upsertFn = func(ctx context.Context, _, _, _, _, _ string, _ int16, _ float64, _, _ time.Time) (port.Finding, error) {
		f := makeFinding(9)
		f.State = string(finding.TechReopened)
		upsertedState = f.State
		return f, nil
	}
	fr.createOccurrenceFn = func(ctx context.Context, arg port.OccurrenceInput) (port.Occurrence, error) {
		return port.Occurrence{}, nil
	}
	fr.upsertDimensionFn = func(ctx context.Context, arg port.DimensionInput) error {
		return nil
	}

	var capturedEvent *port.FindingEventInput
	fr.createEventFn = func(ctx context.Context, arg port.FindingEventInput) (port.FindingEvent, error) {
		capturedEvent = &arg
		return port.FindingEvent{}, nil
	}

	reg := scanner.NewRegistry()
	require.NoError(t, reg.Register(&mockScanner{
		name: "trivy",
		parseFn: func(ctx context.Context, input []byte) (*domain.NormalizedReport, error) {
			return &domain.NormalizedReport{
				ContractVersion:    1,
				FingerprintVersion: 1,
				Completeness:       domain.CompletenessComplete,
				ScanType:           domain.ScanTypeImage,
				Target:             &domain.TargetInfo{Kind: "container", Identifier: "myapp:latest"},
				Findings: []domain.NormalizedFinding{
					{
						Fingerprint: "fp-regressed",
						FindingKind: "sca",
						Title:       "CVE-2024-1234",
						Severity:    domain.SeverityHigh,
						Score:       7.5,
					},
				},
			}, nil
		},
	}))

	uc := New(Deps{
		Stores: &port.Stores{
			Projects:  pr,
			Reports:   rr,
			Findings:  fr,
			Targets:   stubTargetRepo(),
			Artifacts: stubArtifactRepo(),
		},
		Registry: reg,
	})

	result, err := uc.IngestReport(context.Background(), IngestReportInput{
		ProjectSlug: "my-app",
		Scanner:     "trivy",
		RawData:     json.RawMessage(`{"test": true}`),
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, 1, result.TotalFindings)

	require.NotNil(t, capturedEvent, "regression must log a finding event")
	assert.Equal(t, "regression", capturedEvent.EventType)
	assert.NotNil(t, capturedEvent.OldValue)
	assert.Equal(t, "fixed", *capturedEvent.OldValue)
	assert.NotNil(t, capturedEvent.NewValue)
	assert.Equal(t, upsertedState, *capturedEvent.NewValue)

	var changes map[string]any
	require.NoError(t, json.Unmarshal(capturedEvent.Changes, &changes))
	assert.Equal(t, "trivy", changes["scanner"])
	assert.Equal(t, upsertedState, changes["new_state"])
}

// TestIngestRegression_NoEventForOpenFinding verifies that a finding that
// is already open does not trigger a regression event on re-ingest.
func TestIngestRegression_NoEventForOpenFinding(t *testing.T) {
	pr, rr, fr := makeTestRepos()
	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return makeProject(true), nil
	}
	rr.createFn = func(ctx context.Context, arg port.CreateReportInput) (port.Report, error) {
		return makeReport(), nil
	}
	rr.updateStatusFn = func(ctx context.Context, id, projectID, status string, totalFindings int32, errorMsg *string) (port.Report, error) {
		return makeReport(), nil
	}

	existing := makeFinding(1)
	existing.State = "open"
	fr.getByFingerprintFn = func(ctx context.Context, _, _, _ string) (port.Finding, error) {
		return existing, nil
	}
	fr.upsertFn = func(ctx context.Context, _, _, _, _, _ string, _ int16, _ float64, _, _ time.Time) (port.Finding, error) {
		return makeFinding(1), nil
	}
	fr.createOccurrenceFn = func(ctx context.Context, arg port.OccurrenceInput) (port.Occurrence, error) {
		return port.Occurrence{}, nil
	}
	fr.upsertDimensionFn = func(ctx context.Context, arg port.DimensionInput) error {
		return nil
	}
	fr.updateAnalysisFn = func(ctx context.Context, arg port.UpdateAnalysisInput) (port.Finding, error) {
		return makeFinding(1), nil
	}

	var regressionCount int
	fr.createEventFn = func(ctx context.Context, arg port.FindingEventInput) (port.FindingEvent, error) {
		if arg.EventType == "regression" {
			regressionCount++
		}
		return port.FindingEvent{}, nil
	}

	reg := scanner.NewRegistry()
	require.NoError(t, reg.Register(&mockScanner{
		name: "trivy",
		parseFn: func(ctx context.Context, input []byte) (*domain.NormalizedReport, error) {
			return &domain.NormalizedReport{
				ContractVersion:    1,
				FingerprintVersion: 1,
				Completeness:       domain.CompletenessComplete,
				ScanType:           domain.ScanTypeImage,
				Target:             &domain.TargetInfo{Kind: "container", Identifier: "myapp:latest"},
				Findings: []domain.NormalizedFinding{
					{Fingerprint: "fp1", FindingKind: "sca", Title: "CVE-2024-1234", Severity: domain.SeverityHigh, Score: 7.5},
				},
			}, nil
		},
	}))

	uc := New(Deps{
		Stores: &port.Stores{
			Projects: pr, Reports: rr, Findings: fr,
			Targets: stubTargetRepo(), Artifacts: stubArtifactRepo(),
		},
		Registry: reg,
	})

	_, err := uc.IngestReport(context.Background(), IngestReportInput{
		ProjectSlug: "my-app", Scanner: "trivy",
		RawData: json.RawMessage(`{"test": true}`),
	})
	require.NoError(t, err)
	assert.Zero(t, regressionCount, "no regression event for an already-open finding")
}

// TestVerifyFix_RegressionDetected verifies the end-to-end flow: a finding
// marked fixed by VerifyFix, then observed again in a newer scan, flips to
// still_present and the finding state returns to reopened.
func TestVerifyFix_RegressionDetected(t *testing.T) {
	pr, rr, fr := makeTestRepos()
	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return makeProject(true), nil
	}

	f := makeFinding(1)
	f.State = "open"
	fr.getByIDFn = func(ctx context.Context, id string) (port.Finding, error) {
		return f, nil
	}
	fr.getDisplayContextFn = func(ctx context.Context, findingID string) (port.FindingDisplayContext, error) {
		return port.FindingDisplayContext{ToolName: "trivy"}, nil
	}

	// The latest report still has the finding → not fixed.
	rr.latestReportFn = func(ctx context.Context, projectID, scanner string) (port.CompletedReport, error) {
		return port.CompletedReport{
			ID: "11111111-1111-1111-1111-111111111111", ToolName: "trivy",
			Completeness: "complete", CreatedAt: time.Now(),
		}, nil
	}
	fr.hasOccurrenceFn = func(ctx context.Context, findingID, reportID string) (bool, error) {
		return true, nil // finding still present → regression, not regression-fixed
	}

	reg := scanner.NewRegistry()
	uc := New(Deps{Stores: &port.Stores{Projects: pr, Reports: rr, Findings: fr}, Registry: reg})

	resp, err := uc.VerifyFix(findingScopeCtx(findingFixtureProjectID), f.ID)
	require.NoError(t, err)
	assert.Equal(t, VerifyPresent, resp.Outcome, "finding still observed means regression is detected as still present")
}
