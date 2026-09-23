//go:build integration

package repo

import (
	"context"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minh-tg/specht/internal/parser"
	"github.com/minh-tg/specht/internal/scanner"
	"github.com/minh-tg/specht/internal/usecase"
	"github.com/stretchr/testify/require"
)

type ingestQueryCounter struct{ count atomic.Int64 }

func (c *ingestQueryCounter) TraceQueryStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryStartData) context.Context {
	c.count.Add(1)
	return ctx
}

func (*ingestQueryCounter) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func TestIngestBatchQueryCountRegression(t *testing.T) {
	basePool, cleanup := setupIngestPool(t)
	defer cleanup()

	counter := &ingestQueryCounter{}
	poolConfig := basePool.Config()
	poolConfig.ConnConfig.Tracer = counter
	pool, err := pgxpool.NewWithConfig(context.Background(), poolConfig)
	requireNoError(t, err)
	defer pool.Close()

	ctx := context.Background()
	stores := NewPortStores(pool)
	creator, err := stores.Users.Create(ctx, "ingest-profile@example.com", nil, nil)
	requireNoError(t, err)

	registry := scanner.NewRegistry()
	for _, sc := range parser.Builtins() {
		requireNoError(t, registry.Register(sc))
	}
	uc := usecase.New(usecase.Deps{Stores: stores, Registry: registry})
	_, err = uc.CreateProject(globalAdminCtx(creator.ID), "Ingest profile", "ingest-profile", "validation", creator.ID)
	requireNoError(t, err)

	type sample struct {
		findings int
		queries  int64
	}
	samples := make([]sample, 0, 3)
	for _, size := range []int{50, 100, 501} {
		raw := syntheticTrivyReport(t, size)
		counter.count.Store(0)
		start := time.Now()
		_, err := uc.IngestReport(ctx, usecase.IngestReportInput{
			ProjectSlug: "ingest-profile",
			Scanner:     "trivy",
			RawData:     raw,
		})
		elapsed := time.Since(start)
		requireNoError(t, err)

		queries := counter.count.Load()
		samples = append(samples, sample{findings: size, queries: queries})
		t.Logf("findings=%d queries=%d elapsed=%s queries/finding=%.2f", size, queries, elapsed, float64(queries)/float64(size))
		require.LessOrEqual(t, float64(queries)/float64(size), 3.5, "bulk ingestion should stay near three per-finding writes plus fixed report overhead")
	}

	for i := 1; i < len(samples); i++ {
		additionalFindings := samples[i].findings - samples[i-1].findings
		additionalQueries := samples[i].queries - samples[i-1].queries
		queriesPerAdditionalFinding := float64(additionalQueries) / float64(additionalFindings)
		require.LessOrEqual(t, queriesPerAdditionalFinding, 3.5, "query growth should remain bounded as the report grows")
	}
}

func syntheticTrivyReport(t *testing.T, count int) []byte {
	t.Helper()
	vulnerabilities := make([]map[string]any, count)
	for i := range vulnerabilities {
		name := fmt.Sprintf("profile-%d-%d", count, i)
		vulnerabilities[i] = map[string]any{
			"VulnerabilityID":  fmt.Sprintf("CVE-2026-%07d", count*10000+i),
			"PkgName":          name,
			"PkgIdentifier":    map[string]string{"PURL": "pkg:npm/" + name + "@1.0.0"},
			"InstalledVersion": "1.0.0",
			"FixedVersion":     "1.0.1",
			"Severity":         "MEDIUM",
			"Title":            "synthetic profiling finding",
		}
	}

	report, err := json.Marshal(map[string]any{
		"SchemaVersion": 2,
		"ArtifactName":  "ingest-profile-artifact",
		"ArtifactType":  "filesystem",
		"Results": []map[string]any{{
			"Target":          "ingest-profile-target",
			"Class":           "lang-pkgs",
			"Type":            "npm",
			"Vulnerabilities": vulnerabilities,
		}},
	})
	requireNoError(t, err)
	return report
}

func requireNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
