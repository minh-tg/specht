//go:build integration

package repo

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/parser"
	"github.com/minh-tg/specht/internal/port"
	"github.com/minh-tg/specht/internal/scanner"
	"github.com/minh-tg/specht/internal/usecase"
)

func TestIngestFirstAvailableFixFlagsReview(t *testing.T) {
	pool, cleanup := setupIngestPool(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(pool)
	project, err := stores.Projects.Create(ctx, port.CreateProjectInput{Slug: "fix-probe", Name: "Fix Probe", DeploymentThreshold: "high", Settings: []byte(`{}`)})
	require.NoError(t, err)
	registry := scanner.NewRegistry()
	for _, sc := range parser.Builtins() {
		require.NoError(t, registry.Register(sc))
	}
	uc := usecase.New(usecase.Deps{Stores: stores, Registry: registry})
	report := func(fixed string) json.RawMessage {
		raw, err := json.Marshal(map[string]any{
			"SchemaVersion": 2, "ArtifactName": "probe-image", "ArtifactType": "container_image",
			"Results": []map[string]any{{
				"Target": "probe-image (alpine)", "Class": "os-pkgs", "Type": "alpine",
				"Vulnerabilities": []map[string]any{{
					"VulnerabilityID": "CVE-2030-0001", "PkgName": "openssl", "InstalledVersion": "1.0.0",
					"FixedVersion": fixed, "Severity": "HIGH", "Title": "probe vulnerability",
					"PkgIdentifier": map[string]string{"PURL": "pkg:apk/alpine/openssl@1.0.0"},
				}},
			}},
		})
		require.NoError(t, err)
		return raw
	}
	_, err = uc.IngestReport(ctx, usecase.IngestReportInput{ProjectSlug: "fix-probe", Scanner: "trivy", RawData: report("")})
	require.NoError(t, err)
	findings, err := stores.Findings.ListByProject(ctx, project.ID, port.ListFindingsParams{Limit: 10})
	require.NoError(t, err)
	require.Len(t, findings, 1)
	_, err = pool.Exec(ctx, `UPDATE findings SET analysis_state='false_positive', gate_effect='ignore' WHERE id=$1`, findings[0].ID)
	require.NoError(t, err)

	_, err = uc.IngestReport(ctx, usecase.IngestReportInput{ProjectSlug: "fix-probe", Scanner: "trivy", RawData: report("1.0.1")})
	require.NoError(t, err)
	var eventType string
	require.NoError(t, pool.QueryRow(ctx, `SELECT event_type FROM finding_events WHERE event_type='reopened_fix_available'`).Scan(&eventType))
	var review bool
	require.NoError(t, pool.QueryRow(ctx, `SELECT review_required FROM findings`).Scan(&review))
	require.True(t, review)
}
