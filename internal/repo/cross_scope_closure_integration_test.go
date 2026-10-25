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

type branchIngest struct {
	ctx  context.Context
	pool *pgxpool.Pool
	uc   *usecase.Usecases
	slug string
	n    int
}

func newBranchIngest(t *testing.T, slug string) (*branchIngest, func()) {
	t.Helper()
	pool, cleanup := setupIngestPool(t)
	ctx := context.Background()
	stores := NewPortStores(pool)
	_, err := stores.Projects.Create(ctx, port.CreateProjectInput{Slug: slug, Name: slug, DeploymentThreshold: "high", Settings: []byte(`{}`)})
	require.NoError(t, err)
	registry := scanner.NewRegistry()
	for _, sc := range parser.Builtins() {
		require.NoError(t, registry.Register(sc))
	}
	return &branchIngest{ctx: ctx, pool: pool, uc: usecase.New(usecase.Deps{Stores: stores, Registry: registry}), slug: slug}, cleanup
}

// scan uploads a Trivy image scan of branch and returns its report id.
func (b *branchIngest) scan(t *testing.T, branch string, vulnerable bool) string {
	t.Helper()
	b.n++
	tag := string(rune('a' + b.n))
	out, err := b.uc.IngestReport(b.ctx, usecase.IngestReportInput{
		ProjectSlug: b.slug, Scanner: "trivy", Branch: branch,
		CommitSha: "c0ffee0" + tag, RawData: scopedTrivyReport(t, tag, vulnerable),
	})
	require.NoError(t, err)
	return out.ReportID
}

func (b *branchIngest) state(t *testing.T) string {
	t.Helper()
	var state string
	require.NoError(t, b.pool.QueryRow(b.ctx, `SELECT state FROM findings`).Scan(&state))
	return state
}

func (b *branchIngest) scopes(t *testing.T) int {
	t.Helper()
	var n int
	require.NoError(t, b.pool.QueryRow(b.ctx, `SELECT count(*) FROM finding_scope_severities`).Scan(&n))
	return n
}

func TestFindingSeenOnTwoBranchesClosesWhenBothAreClean(t *testing.T) {
	b, cleanup := newBranchIngest(t, "two-branches")
	defer cleanup()
	b.scan(t, "main", true)
	b.scan(t, "feature", true)
	b.scan(t, "feature", false)
	require.Equal(t, "open", b.state(t), "main still observes the finding")
	require.Equal(t, 1, b.scopes(t))

	b.scan(t, "main", false)
	require.Zero(t, b.scopes(t))
	require.Equal(t, "fixed", b.state(t), "every scope that saw the finding has a newer clean scan")
}

func TestStuckCrossBranchFindingClosesOnTheNextCleanScan(t *testing.T) {
	b, cleanup := newBranchIngest(t, "stuck-branches")
	defer cleanup()
	b.scan(t, "main", true)
	b.scan(t, "feature", true)
	b.scan(t, "feature", false)
	b.scan(t, "main", false)
	// A finding left open with no active scope by the earlier closure rule.
	_, err := b.pool.Exec(b.ctx, `UPDATE findings SET state = 'open'`)
	require.NoError(t, err)

	b.scan(t, "main", false)
	require.Equal(t, "fixed", b.state(t))
}

func TestCleanScanOfAnotherBranchNeverClosesMainsFinding(t *testing.T) {
	b, cleanup := newBranchIngest(t, "other-branch")
	defer cleanup()
	b.scan(t, "main", true)
	b.scan(t, "feature", false)
	require.Equal(t, "open", b.state(t), "feature never observed the finding")
	require.Equal(t, 1, b.scopes(t))
}

func TestCleanScanOfABranchThatNeverSawTheFindingDoesNotCloseIt(t *testing.T) {
	b, cleanup := newBranchIngest(t, "unseen-branch")
	defer cleanup()
	b.scan(t, "feature", true)
	b.scan(t, "feature", false)
	require.Equal(t, "fixed", b.state(t))
	b.scan(t, "main", true)
	require.Equal(t, "reopened", b.state(t))
	// Drop main's evidence row the way a report delete with no other main
	// evidence would; only a scan of a scope that observed it may close it.
	_, err := b.pool.Exec(b.ctx, `DELETE FROM finding_scope_severities`)
	require.NoError(t, err)
	b.scan(t, "release", false)
	require.Equal(t, "reopened", b.state(t), "release never observed the finding")
}
