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

// ingestKnownFinding ingests one finding whose stored row is in the given
// state and returns the result plus the events written for it.
func ingestKnownFinding(t *testing.T, storedState string) (*IngestReportOutput, []string) {
	t.Helper()
	pr, rr, fr := makeTestRepos()
	pr.getBySlugFn = func(context.Context, string) (port.Project, error) { return makeProject(true), nil }
	rr.createFn = func(context.Context, port.CreateReportInput) (port.Report, error) { return makeReport(), nil }
	rr.updateStatusFn = func(context.Context, string, string, string, int32, *string) (port.Report, error) {
		return makeReport(), nil
	}
	existing := makeFinding(1)
	existing.State = storedState
	existing.AnalysisState = "unanalyzed"
	fr.getByFingerprintFn = func(context.Context, string, string, string) (port.Finding, error) { return existing, nil }
	fr.upsertFn = func(context.Context, port.UpsertFindingInput) (port.Finding, error) { return makeFinding(1), nil }
	fr.createOccurrenceFn = func(context.Context, port.OccurrenceInput) (port.Occurrence, error) { return port.Occurrence{}, nil }
	fr.upsertDimensionFn = func(context.Context, port.DimensionInput) error { return nil }
	var events []string
	fr.createEventFn = func(_ context.Context, in port.FindingEventInput) (port.FindingEvent, error) {
		events = append(events, in.EventType)
		return port.FindingEvent{}, nil
	}

	reg := scanner.NewRegistry()
	require.NoError(t, reg.Register(&mockScanner{
		name: "trivy",
		parseFn: func(context.Context, []byte) (*domain.NormalizedReport, error) {
			return &domain.NormalizedReport{
				ContractVersion: 1, FingerprintVersion: 1,
				Completeness: domain.CompletenessComplete, ScanType: domain.ScanTypeImage,
				CoveredFindingKinds: []string{"sca", "sast", "iac", "secret", "dast"},
				Target:              &domain.TargetInfo{Kind: "container", Identifier: "myapp:latest"},
				Findings: []domain.NormalizedFinding{
					{Fingerprint: "fp1", FindingKind: "sca", Title: "CVE-2024-1234", Severity: domain.SeverityHigh, Score: 7.5},
				},
			}, nil
		},
	}))
	uc := New(Deps{
		Stores:   &port.Stores{Projects: pr, Reports: rr, Findings: fr, Targets: stubTargetRepo(), Artifacts: stubArtifactRepo()},
		Registry: reg,
	})

	result, err := uc.IngestReport(context.Background(), IngestReportInput{
		ProjectSlug: "my-app", Scanner: "trivy", RawData: json.RawMessage(`{"test": true}`),
	})
	require.NoError(t, err)
	return result, events
}

// A finding archived with its report comes back with a new one. It is new for
// that report, so it is counted as introduced, and it is not a regression:
// nobody had fixed it.
func TestIngest_ArchivedFindingSeenAgainIsIntroducedNotARegression(t *testing.T) {
	result, events := ingestKnownFinding(t, "archived")

	assert.Equal(t, 1, result.IntroducedCount)
	assert.NotContains(t, events, "regression")
}

func TestIngest_OpenFindingSeenAgainPreExists(t *testing.T) {
	result, _ := ingestKnownFinding(t, "open")

	assert.Zero(t, result.IntroducedCount)
}
