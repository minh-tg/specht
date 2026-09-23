package usecase

import (
	"context"
	"errors"
	"testing"

	"github.com/minh-tg/specht/internal/domain"
	"github.com/minh-tg/specht/internal/port"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestApplyMaterialChangePropagatesPreviousFixLookupError(t *testing.T) {
	lookupErr := errors.New("database unavailable")
	var analysisUpdated, eventCreated bool
	findings := &mockFindingRepo{
		hasDimensionFn: func(context.Context, string, string) (bool, error) {
			return false, lookupErr
		},
		updateAnalysisFn: func(context.Context, port.UpdateAnalysisInput) (port.Finding, error) {
			analysisUpdated = true
			return port.Finding{}, nil
		},
		createEventFn: func(context.Context, port.FindingEventInput) (port.FindingEvent, error) {
			eventCreated = true
			return port.FindingEvent{}, nil
		},
	}
	uc := New(Deps{Stores: &port.Stores{Findings: findings}})

	err := uc.applyMaterialChange(
		context.Background(),
		IngestReportInput{Scanner: "trivy"},
		port.Finding{ID: "finding-1"},
		domain.NormalizedFinding{
			Severity: domain.SeverityMedium,
			Dimensions: []domain.Dimension{{
				Key: domain.DimFixedVersion, Value: "2.0.0",
			}},
		},
		int16(domain.SeverityMedium), "block", "in_triage",
	)

	require.ErrorIs(t, err, lookupErr)
	assert.False(t, analysisUpdated, "do not infer a newly available fix when its prior state could not be read")
	assert.False(t, eventCreated, "do not record a material-change event from an unknown prior state")
}
