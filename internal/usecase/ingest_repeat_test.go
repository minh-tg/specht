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

// A report can name one finding thousands of times (a SARIF run with many
// results in one file and rule). Every write to the same row inside the
// ingest transaction makes the next one slower, so the writes per finding must
// not grow with the number of entries.
func TestIngestReport_AFindingNamedManyTimesWritesItsRowAtMostTwice(t *testing.T) {
	const entries = 500
	uc, fr, _ := autofixHarness(t, domain.CompletenessUnknown)
	var upserts, attributions, fixDimensions int
	var lastTitle, lastSeverity string
	upsert := fr.upsertFn
	fr.upsertFn = func(ctx context.Context, in port.UpsertFindingInput) (port.Finding, error) {
		upserts++
		lastTitle, lastSeverity = in.Title, in.Severity
		return upsert(ctx, in)
	}
	fr.setIntroducedByFn = func(_ context.Context, id, _ string, _ *string) (port.Finding, error) {
		attributions++
		return port.Finding{ID: id}, nil
	}
	fr.upsertDimensionFn = func(_ context.Context, d port.DimensionInput) error {
		if d.Key == domain.DimFixedVersion {
			fixDimensions++
		}
		return nil
	}
	findings := make([]domain.NormalizedFinding, entries)
	for i := range findings {
		severity := domain.SeverityLow
		if i%2 == 0 {
			severity = domain.SeverityHigh
		}
		findings[i] = domain.NormalizedFinding{
			Fingerprint: "sast:r:a.go", FindingKind: "sast", Title: fmt.Sprintf("entry %d", i), Severity: severity,
			Dimensions: []domain.Dimension{{Key: domain.DimFixedVersion, Value: "1.2.3"}, {Key: domain.DimLine, Value: fmt.Sprint(i)}},
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

	out, err := uc.IngestReport(context.Background(), IngestReportInput{
		ProjectSlug: "my-app", Scanner: "repeat", RawData: json.RawMessage(`{"a":1}`),
	})

	require.NoError(t, err)
	assert.Equal(t, entries, out.TotalFindings, "every entry still counts")
	assert.Equal(t, 1, out.IntroducedCount, "the finding is introduced once")
	assert.Equal(t, entries-1, out.PreExistingCount)
	assert.LessOrEqual(t, upserts, 2, "only the first and the last entry write the row")
	assert.Equal(t, 1, attributions, "the introducing report is recorded once")
	assert.Equal(t, 1, fixDimensions, "an unchanged dimension is written once")
	assert.Equal(t, fmt.Sprintf("entry %d", entries-1), lastTitle, "the last entry sets the title")
	assert.Equal(t, "low", lastSeverity, "and the severity")
}
