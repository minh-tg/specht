package usecase

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/port"
)

func TestRawExpiresAt_DatesOnlyAnExpiredPayloadUnderAWindow(t *testing.T) {
	created := time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC)
	dated := created.Add(30 * 24 * time.Hour)
	cases := map[string]struct {
		expired bool
		days    int
		want    *time.Time
	}{
		"kept payload has no date":      {expired: false, days: 30, want: nil},
		"no window has no date":         {expired: true, days: 0, want: nil},
		"expired payload is dated":      {expired: true, days: 30, want: &dated},
		"window is applied in full UTC": {expired: true, days: 1, want: timeAt(created.Add(24 * time.Hour))},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, rawExpiresAt(created, tc.expired, tc.days))
		})
	}
}

func timeAt(t time.Time) *time.Time { return &t }

func TestGetReport_ExpiredRawDataIsDatedByTheWindow(t *testing.T) {
	created := time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC)
	report := makeReport()
	report.CreatedAt = created
	report.RawDataExpired = true
	rr := &mockReportRepo{}
	rr.getByIDFn = func(ctx context.Context, id string) (port.Report, error) {
		return report, nil
	}
	uc := New(Deps{
		Stores:           &port.Stores{Reports: rr, Projects: memberProjects()},
		RawRetentionDays: 30,
	})

	resp, err := uc.GetReport(findingScopeCtx(findingFixtureProjectID), report.ID)
	require.NoError(t, err)
	assert.True(t, resp.RawDataExpired)
	require.NotNil(t, resp.RawDataExpiresAt)
	assert.Equal(t, created.Add(30*24*time.Hour), *resp.RawDataExpiresAt)
}

func TestGetReport_KeptRawDataIsNotExpired(t *testing.T) {
	report := makeReport()
	rr := &mockReportRepo{}
	rr.getByIDFn = func(ctx context.Context, id string) (port.Report, error) {
		return report, nil
	}
	uc := New(Deps{
		Stores:           &port.Stores{Reports: rr, Projects: memberProjects()},
		RawRetentionDays: 30,
	})

	resp, err := uc.GetReport(findingScopeCtx(findingFixtureProjectID), report.ID)
	require.NoError(t, err)
	assert.False(t, resp.RawDataExpired)
	assert.Nil(t, resp.RawDataExpiresAt)
}

func TestGetFinding_FlagsTheReportOfItsLatestObservation(t *testing.T) {
	pr, rr, fr := makeTestRepos()
	created := time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC)
	f := makeFinding(1)
	fr.getByIDFn = func(ctx context.Context, id string) (port.Finding, error) {
		return f, nil
	}
	fr.getDisplayContextFn = func(ctx context.Context, findingID string) (port.FindingDisplayContext, error) {
		return port.FindingDisplayContext{ToolName: "trivy", RawDataExpired: true, ReportCreatedAt: created}, nil
	}
	uc := New(Deps{
		Stores:           &port.Stores{Projects: pr, Reports: rr, Findings: fr},
		RawRetentionDays: 30,
	})

	resp, err := uc.GetFinding(findingScopeCtx(findingFixtureProjectID), f.ID)
	require.NoError(t, err)
	require.NotNil(t, resp.RawDataExpired)
	assert.True(t, *resp.RawDataExpired)
	require.NotNil(t, resp.RawDataExpiresAt)
	assert.Equal(t, created.Add(30*24*time.Hour), *resp.RawDataExpiresAt)
}

func TestGetFinding_WithoutAnObservationIsNotExpired(t *testing.T) {
	pr, rr, fr := makeTestRepos()
	f := makeFinding(1)
	fr.getByIDFn = func(ctx context.Context, id string) (port.Finding, error) {
		return f, nil
	}
	fr.getDisplayContextFn = func(ctx context.Context, findingID string) (port.FindingDisplayContext, error) {
		return port.FindingDisplayContext{}, port.ErrNotFound
	}
	uc := New(Deps{
		Stores:           &port.Stores{Projects: pr, Reports: rr, Findings: fr},
		RawRetentionDays: 30,
	})

	resp, err := uc.GetFinding(findingScopeCtx(findingFixtureProjectID), f.ID)
	require.NoError(t, err)
	require.NotNil(t, resp.RawDataExpired)
	assert.False(t, *resp.RawDataExpired)
	assert.Nil(t, resp.RawDataExpiresAt)
}
