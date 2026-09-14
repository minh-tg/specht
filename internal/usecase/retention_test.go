package usecase

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xMinhx/specht/internal/port"
)

func retentionHarness(t *testing.T, count int64, deleted []string) (*Usecases, *mockReportRepo, *mockAdminRepo) {
	t.Helper()
	pr, rr, fr := makeTestRepos()
	rr.countStaleFn = func(ctx context.Context, cutoff time.Time) (int64, error) {
		assert.WithinDuration(t, time.Now().AddDate(0, 0, -30), cutoff, time.Minute)
		return count, nil
	}
	rr.deleteStaleFn = func(ctx context.Context, cutoff time.Time) ([]string, error) {
		return deleted, nil
	}
	ar := &mockAdminRepo{}
	uc := New(Deps{Stores: &port.Stores{
		Projects: pr, Reports: rr, Findings: fr, Admin: ar,
	}})
	return uc, rr, ar
}

func TestPreviewRetention_Counts(t *testing.T) {
	uc, _, _ := retentionHarness(t, 7, nil)
	out, err := uc.PreviewRetention(context.Background(), 30)
	require.NoError(t, err)
	assert.Equal(t, 30, out.OlderThanDays)
	assert.Equal(t, int64(7), out.StaleReports)
}

func TestPreviewRetention_RejectsBadWindows(t *testing.T) {
	uc, _, _ := retentionHarness(t, 0, nil)
	_, err := uc.PreviewRetention(context.Background(), 0)
	require.Error(t, err)
	_, err = uc.PreviewRetention(context.Background(), -5)
	require.Error(t, err)
	_, err = uc.PreviewRetention(context.Background(), 3651)
	require.Error(t, err)
}

func TestPurgeRetention_Deletes(t *testing.T) {
	uc, _, _ := retentionHarness(t, 0, []string{"r1", "r2"})
	out, err := uc.PurgeRetention(context.Background(), 30)
	require.NoError(t, err)
	assert.Equal(t, int64(2), out.DeletedReports)
	assert.Equal(t, []string{"r1", "r2"}, out.DeletedReportIDs)
	_, err = uc.PurgeRetention(context.Background(), 0)
	require.Error(t, err)
}

func TestGetAdminStatus_Maps(t *testing.T) {
	uc, _, ar := retentionHarness(t, 0, nil)
	oldest := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	ar.overviewFn = func(ctx context.Context) (port.AdminOverview, error) {
		return port.AdminOverview{
			ProjectCount: 3, UserCount: 10, OpenFindingCount: 42,
			ReportCount: 100, OldestSettledReportAt: &oldest,
		}, nil
	}
	out, err := uc.GetAdminStatus(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int64(3), out.Projects)
	assert.Equal(t, int64(42), out.OpenFindings)
	require.NotNil(t, out.OldestSettledReportAt)
	assert.True(t, oldest.Equal(*out.OldestSettledReportAt))
}
