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

func TestPartialTrivyScanDoesNotCloseVulnerabilityFindings(t *testing.T) {
	pool, cleanup := setupIngestPool(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(pool)
	project, err := stores.Projects.Create(ctx, port.CreateProjectInput{Slug: "trivy-scope", Name: "Trivy Scope", DeploymentThreshold: "high", Settings: []byte(`{}`)})
	require.NoError(t, err)
	registry := scanner.NewRegistry()
	for _, sc := range parser.Builtins() {
		require.NoError(t, registry.Register(sc))
	}
	uc := usecase.New(usecase.Deps{Stores: stores, Registry: registry})
	vulnReport := map[string]any{
		"SchemaVersion": 2, "ArtifactName": "app:1", "ArtifactType": "container_image",
		"Results": []map[string]any{{
			"Target": "app:1 (alpine)", "Class": "os-pkgs", "Type": "alpine",
			"Vulnerabilities": []map[string]any{{
				"VulnerabilityID": "CVE-2031-0001", "PkgName": "openssl", "InstalledVersion": "1.0",
				"Severity": "CRITICAL", "Title": "openssl flaw",
				"PkgIdentifier": map[string]string{"PURL": "pkg:apk/alpine/openssl@1.0"},
			}},
		}},
	}
	rawVuln, err := json.Marshal(vulnReport)
	require.NoError(t, err)
	_, err = uc.IngestReport(ctx, usecase.IngestReportInput{ProjectSlug: "trivy-scope", Scanner: "trivy", Branch: "main", CommitSha: "aaaa1111", RawData: rawVuln})
	require.NoError(t, err)

	secretReport := map[string]any{
		"SchemaVersion": 2, "ArtifactName": "app:1", "ArtifactType": "container_image",
		"Results": []map[string]any{{
			"Target": "Dockerfile", "Class": "secret", "Type": "dockerfile",
			"Secrets": []map[string]any{{"RuleID": "generic-api-key", "Title": "Secret", "Severity": "HIGH", "Match": "redacted"}},
		}},
	}
	rawSecret, err := json.Marshal(secretReport)
	require.NoError(t, err)
	_, err = uc.IngestReport(ctx, usecase.IngestReportInput{ProjectSlug: "trivy-scope", Scanner: "trivy", Branch: "main", CommitSha: "bbbb2222", RawData: rawSecret})
	require.NoError(t, err)

	var state, severity string
	require.NoError(t, pool.QueryRow(ctx, `SELECT state, current_severity FROM findings WHERE project_id=$1 AND fingerprint LIKE '%CVE-2031-0001%'`, project.ID).Scan(&state, &severity))
	require.Equal(t, "open", state, "a secret-only scan says nothing about vulnerabilities")
	require.Equal(t, "critical", severity, "the vulnerability scope evidence must survive")
	var scopes int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM finding_scope_severities WHERE finding_id = (SELECT id FROM findings WHERE project_id=$1 AND fingerprint LIKE '%CVE-2031-0001%')`, project.ID).Scan(&scopes))
	require.Equal(t, 1, scopes)
}

// scopedTrivyReport is a Trivy image report for app:<tag>. With vulnerable
// set it names one CVE, otherwise the image scan is clean.
func scopedTrivyReport(t *testing.T, tag string, vulnerable bool) []byte {
	t.Helper()
	vulns := []map[string]any{}
	if vulnerable {
		vulns = append(vulns, map[string]any{
			"VulnerabilityID": "CVE-2033-0001", "PkgName": "openssl", "InstalledVersion": "1.0",
			"Severity": "HIGH", "Title": "openssl flaw",
			"PkgIdentifier": map[string]string{"PURL": "pkg:apk/alpine/openssl@1.0"},
		})
	}
	raw, err := json.Marshal(map[string]any{
		"SchemaVersion": 2, "ArtifactName": "app:" + tag, "ArtifactType": "container_image",
		"Results": []map[string]any{{
			"Target": "app:" + tag + " (alpine)", "Class": "os-pkgs", "Type": "alpine",
			"Vulnerabilities": vulns,
		}},
	})
	require.NoError(t, err)
	return raw
}

func TestIncrementalUploadFallingBackToFullClosesNothing(t *testing.T) {
	pool, cleanup := setupIngestPool(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(pool)
	_, err := stores.Projects.Create(ctx, port.CreateProjectInput{Slug: "fallback", Name: "Fallback", DeploymentThreshold: "high", Settings: []byte(`{}`)})
	require.NoError(t, err)
	registry := scanner.NewRegistry()
	for _, sc := range parser.Builtins() {
		require.NoError(t, registry.Register(sc))
	}
	uc := usecase.New(usecase.Deps{Stores: stores, Registry: registry})
	_, err = uc.IngestReport(ctx, usecase.IngestReportInput{ProjectSlug: "fallback", Scanner: "trivy", Branch: "main", CommitSha: "aaaa1111", RawData: scopedTrivyReport(t, "1", true)})
	require.NoError(t, err)

	out, err := uc.IngestReport(ctx, usecase.IngestReportInput{
		ProjectSlug: "fallback", Scanner: "trivy", Branch: "main", CommitSha: "aaaa2222",
		RawData:  scopedTrivyReport(t, "2", false),
		ScanMode: "incremental", BaseRevision: "aaaa1111", ChangedFiles: []string{"go.mod"},
	})
	require.NoError(t, err)
	require.Equal(t, "full", out.ScanMode, "the response still names the mode used")
	require.NotEmpty(t, out.FallbackReason)
	require.True(t, out.ThresholdBreached, "the open finding still blocks")

	var state string
	require.NoError(t, pool.QueryRow(ctx, `SELECT state FROM findings`).Scan(&state))
	require.Equal(t, "open", state, "a scan the caller called incremental proves nothing by absence")
	var completeness string
	require.NoError(t, pool.QueryRow(ctx, `SELECT scan_completeness FROM reports WHERE id = $1`, out.ReportID).Scan(&completeness))
	require.Equal(t, "partial", completeness)
}
