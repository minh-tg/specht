package usecase

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/port"
)

func TestPurgeRetentionStopsAtTheRunLimitAndReportsTheRest(t *testing.T) {
	pr, rr, fr := makeTestRepos()
	full := make([]string, maxPurgeReportsPerRun)
	for i := range full {
		full[i] = "r"
	}
	var counted int
	rr.deleteStaleFn = func(context.Context, time.Time, int) ([]string, error) { return full, nil }
	rr.countStaleFn = func(context.Context, time.Time) (int64, error) { counted++; return 17, nil }
	uc := New(Deps{Stores: &port.Stores{Projects: pr, Reports: rr, Findings: fr}})

	out, err := uc.PurgeRetention(context.Background(), 30)
	require.NoError(t, err)
	assert.Equal(t, int64(maxPurgeReportsPerRun), out.DeletedReports)
	assert.Equal(t, int64(17), out.Remaining)
	assert.Equal(t, 1, counted)
}

func TestPurgeRetentionOmitsRemainingWhenItClearsTheCutoff(t *testing.T) {
	pr, rr, fr := makeTestRepos()
	rr.deleteStaleFn = func(context.Context, time.Time, int) ([]string, error) { return []string{"r"}, nil }
	rr.countStaleFn = func(context.Context, time.Time) (int64, error) {
		t.Fatal("a short run must not need a second count")
		return 0, nil
	}
	uc := New(Deps{Stores: &port.Stores{Projects: pr, Reports: rr, Findings: fr}})

	out, err := uc.PurgeRetention(context.Background(), 30)
	require.NoError(t, err)
	assert.Zero(t, out.Remaining)
}
