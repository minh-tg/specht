//go:build integration

package repo

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/parser"
	"github.com/minh-tg/specht/internal/port"
	"github.com/minh-tg/specht/internal/scanner"
	"github.com/minh-tg/specht/internal/usecase"
)

// TestReadPathQueryBudget guards the read surfaces against N+1 growth —
// the mirror of the ingest budget test: page-size growth must not scale
// queries with rows, and composed single-item reads stay within fixed
// caps. A regression here means list/detail started querying per row.
func TestReadPathQueryBudget(t *testing.T) {
	basePool, cleanup := setupIngestPool(t)
	defer cleanup()
	counter := &ingestQueryCounter{}
	poolConfig := basePool.Config()
	poolConfig.ConnConfig.Tracer = counter
	pool, err := pgxpool.NewWithConfig(context.Background(), poolConfig)
	require.NoError(t, err)
	defer pool.Close()

	ctx := context.Background()
	stores := NewPortStores(pool)
	creator, err := stores.Users.Create(ctx, "read-budget@example.com", nil, nil)
	require.NoError(t, err)

	registry := scanner.NewRegistry()
	for _, sc := range parser.Builtins() {
		require.NoError(t, registry.Register(sc))
	}
	uc := usecase.New(usecase.Deps{Stores: stores, Registry: registry})
	_, err = uc.CreateProject(globalAdminCtx(creator.ID),
		"Read budget", "read-budget", "validation", creator.ID)
	require.NoError(t, err)
	_, err = uc.IngestReport(ctx, usecase.IngestReportInput{
		ProjectSlug: "read-budget",
		Scanner:     "trivy",
		RawData:     syntheticTrivyReport(t, 50),
	})
	require.NoError(t, err)

	project, err := stores.Projects.GetBySlug(ctx, "read-budget")
	require.NoError(t, err)

	measure := func(fn func()) int64 {
		counter.count.Store(0)
		fn()
		return counter.count.Load()
	}

	listPage := func(limit int32) []port.Finding {
		rows, lerr := stores.Findings.ListByProject(ctx, project.ID, port.ListFindingsParams{
			Limit: limit, Offset: 0,
		})
		require.NoError(t, lerr)
		return rows
	}

	q10 := measure(func() { listPage(10) })
	q50 := measure(func() { listPage(50) })
	t.Logf("list: q(10)=%d q(50)=%d", q10, q50)
	require.LessOrEqual(t, float64(q50-q10)/40.0, 0.5,
		"findings list must not query per row (N+1 regression)")

	rows := listPage(10)
	require.NotEmpty(t, rows)
	var detail *usecase.FindingResponse
	// Reads go through the access-checking usecase, so they carry the
	// admin identity like every real request does.
	actx := globalAdminCtx(creator.ID)
	qDetail := measure(func() {
		var derr error
		detail, derr = uc.GetFinding(actx, rows[0].ID)
		require.NoError(t, derr, "finding detail must read cleanly")
	})
	require.NotNil(t, detail)
	t.Logf("get finding: q=%d", qDetail)
	require.LessOrEqual(t, qDetail, int64(6),
		"finding detail is a fixed set of reads (row, display context, dimensions)")

	qReports := measure(func() {
		_, rerr := uc.ListReports(actx, "read-budget", 50, 0)
		require.NoError(t, rerr, "report history must read cleanly")
	})
	t.Logf("list reports: q=%d", qReports)
	require.LessOrEqual(t, qReports, int64(4),
		"report history is one page query plus project lookup")

	qGate := measure(func() {
		_, gerr := uc.GetGateStatus(actx, "read-budget", 3)
		require.NoError(t, gerr, "gate must evaluate cleanly")
	})
	t.Logf("gate: q=%d", qGate)
	require.LessOrEqual(t, qGate, int64(12),
		"gate evaluation reads candidates and waivers once, not per finding")
}
