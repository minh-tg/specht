package usecase

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/port"
)

func TestTriageRejectsExpiredAnalysis(t *testing.T) {
	instant := time.Date(2030, 1, 2, 12, 0, 0, 0, time.UTC)
	for _, delta := range []time.Duration{-time.Second, 0, time.Second} {
		for _, bulk := range []bool{false, true} {
			t.Run(delta.String()+map[bool]string{false: "/single", true: "/bulk"}[bulk], func(t *testing.T) {
				expiry := instant.Add(delta)
				f := makeFindingRow(1)
				writes := 0
				fr := &mockFindingRepo{
					getByIDFn:   func(context.Context, string) (port.Finding, error) { return f, nil },
					listByIDsFn: func(context.Context, []string) ([]port.Finding, error) { return []port.Finding{f}, nil },
					updateAnalysisWithEventFn: func(context.Context, port.UpdateAnalysisInput, port.FindingEventInput) (port.Finding, port.FindingEvent, error) {
						writes++
						return f, port.FindingEvent{}, nil
					},
					bulkTriageFn: func(context.Context, port.UpdateAnalysisInput, []string, port.FindingEventInput) ([]port.Finding, error) {
						writes++
						return []port.Finding{f}, nil
					},
				}
				u := New(Deps{Stores: &port.Stores{Findings: fr, Projects: memberProjects()}, Now: func() time.Time { return instant }})
				ctx := findingScopeCtx(findingFixtureProjectID)
				var err error
				if bulk {
					_, err = u.BulkTriage(ctx, BulkTriageInput{FindingIDs: []string{f.ID}, UserID: findingFixtureProjectID, AnalysisState: "accepted_risk", Reason: "temporary", AnalysisExpiresAt: &expiry})
				} else {
					_, err = u.TriageFinding(ctx, TriageInput{FindingID: f.ID, UserID: findingFixtureProjectID, AnalysisState: "accepted_risk", Reason: "temporary", AnalysisExpiresAt: &expiry})
				}
				if delta <= 0 {
					require.Error(t, err)
					require.Zero(t, writes)
				} else {
					require.NoError(t, err)
					require.Equal(t, 1, writes)
				}
			})
		}
	}
}
