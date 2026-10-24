//go:build integration

package repo

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/parser"
	"github.com/minh-tg/specht/internal/port"
	"github.com/minh-tg/specht/internal/scanner"
	"github.com/minh-tg/specht/internal/usecase"
)

func TestIngestPersistsScannerAliasesAsDimensions(t *testing.T) {
	pool, cleanup := setupIngestPool(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(pool)
	_, err := stores.Projects.Create(ctx, port.CreateProjectInput{Slug: "alias-probe", Name: "Alias Probe", DeploymentThreshold: "high", Settings: []byte(`{}`)})
	require.NoError(t, err)
	registry := scanner.NewRegistry()
	for _, sc := range parser.Builtins() {
		require.NoError(t, registry.Register(sc))
	}
	uc := usecase.New(usecase.Deps{Stores: stores, Registry: registry})
	raw, err := os.ReadFile("../parser/osvscanner/testdata/go-full.json")
	require.NoError(t, err)
	_, err = uc.IngestReport(ctx, usecase.IngestReportInput{ProjectSlug: "alias-probe", Scanner: "osv-scanner", RawData: raw})
	require.NoError(t, err)

	var aliases int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM finding_dimensions WHERE dim_key='alias'`).Scan(&aliases))
	require.Positive(t, aliases, "scanner aliases must reach the dimensions the gate and waivers read")
	var cveAliases int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(DISTINCT dim_value) FROM finding_dimensions WHERE dim_key='alias' AND dim_value LIKE 'CVE-%'`).Scan(&cveAliases))
	require.Positive(t, cveAliases)
}
