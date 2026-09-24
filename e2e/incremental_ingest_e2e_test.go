//go:build e2e

package e2e

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestE2E_IncrementalScanFallbacks pins resolveScanMode's fail-closed
// contract: incremental requests are validated at the boundary, unsupported
// scanners degrade to a full scan with an explicit reason even when a
// baseline exists, and gates never silently pass on omitted coverage.
func TestE2E_IncrementalScanFallbacks(t *testing.T) {
	slug := newProject(t, "incr-fallback")
	key := mintKey(t, slug)

	t.Run("baseline full scan anchors the revision", func(t *testing.T) {
		resp := request[ingestResponse](t, http.MethodPost, "/api/v1/reports", key,
			ingestBodyWith(t, slug, "medium.sarif.json", map[string]any{
				"commit_sha": baseSHA,
			}), http.StatusCreated)
		require.Equal(t, "full", resp.ScanMode)
		require.Empty(t, resp.FallbackReason)
	})

	t.Run("incremental without base_revision is rejected", func(t *testing.T) {
		status, raw := doJSON(t, http.MethodPost, "/api/v1/reports", key,
			ingestBodyWith(t, slug, "high-new.sarif.json", map[string]any{
				"scan_mode": "incremental",
			}))
		require.Equal(t, http.StatusUnprocessableEntity, status)
		require.Contains(t, string(raw), "ingest_failed")
	})

	t.Run("incremental with base_revision equal to commit_sha is rejected", func(t *testing.T) {
		status, raw := doJSON(t, http.MethodPost, "/api/v1/reports", key,
			ingestBodyWith(t, slug, "high-new.sarif.json", map[string]any{
				"scan_mode":     "incremental",
				"commit_sha":    baseSHA,
				"base_revision": baseSHA,
			}))
		require.Equal(t, http.StatusUnprocessableEntity, status)
		require.Contains(t, string(raw), "ingest_failed")
	})

	t.Run("unknown scan modes are rejected", func(t *testing.T) {
		status, raw := doJSON(t, http.MethodPost, "/api/v1/reports", key,
			ingestBodyWith(t, slug, "high-new.sarif.json", map[string]any{
				"scan_mode": "diagonal",
			}))
		require.Equal(t, http.StatusUnprocessableEntity, status)
		require.Contains(t, string(raw), "ingest_failed")
	})

	t.Run("unsupported scanner degrades to full despite a baseline", func(t *testing.T) {
		// The baseline at baseSHA exists (tool "sarif"), so the fallback
		// reason must name the scanner capability, not the missing
		// baseline: capability is checked first.
		resp := request[ingestResponse](t, http.MethodPost, "/api/v1/reports", key,
			ingestBodyWith(t, slug, "high-medium.sarif.json", map[string]any{
				"scan_mode":     "incremental",
				"commit_sha":    "2222222222222222222222222222222222222222",
				"base_revision": baseSHA,
			}), http.StatusCreated)
		require.Equal(t, "full", resp.ScanMode,
			"a scanner without incremental support must record a full scan")
		require.Contains(t, resp.FallbackReason, "does not support incremental")
		require.Equal(t, 2, resp.TotalFindings)
		require.True(t, resp.ThresholdBreached,
			"the fallback full scan must still evaluate the full gate")
	})
}

// TestE2E_IncrementalScanWithBaseline pins the incremental happy path for a
// scanner that opted into incremental analysis: a completed full baseline at
// the base revision keeps the effective scan mode incremental, the missing
// baseline degrades with an explicit reason, and change classification runs
// against the baseline's occurrences. Every request uses scanner "semgrep"
// (the fixtures are SARIF, which semgrep's parser accepts on explicit
// selection) because only incremental-capable scanners keep the mode.
func TestE2E_IncrementalScanWithBaseline(t *testing.T) {
	slug := newProject(t, "incr-baseline")
	key := mintKey(t, slug)

	t.Run("full baseline anchors the revision", func(t *testing.T) {
		resp := request[ingestResponse](t, http.MethodPost, "/api/v1/reports", key,
			ingestBodyWith(t, slug, "high.sarif.json", map[string]any{
				"commit_sha": baseSHA,
				"scanner":    "semgrep",
			}), http.StatusCreated)
		require.Equal(t, "full", resp.ScanMode)
		require.Equal(t, 1, resp.TotalFindings)
		require.True(t, resp.ThresholdBreached)
	})

	t.Run("incremental without a baseline degrades with an explicit reason", func(t *testing.T) {
		resp := request[ingestResponse](t, http.MethodPost, "/api/v1/reports", key,
			ingestBodyWith(t, slug, "medium.sarif.json", map[string]any{
				"scan_mode":     "incremental",
				"commit_sha":    "3333333333333333333333333333333333333333",
				"base_revision": deadSHA,
				"scanner":       "semgrep",
			}), http.StatusCreated)
		require.Equal(t, "full", resp.ScanMode)
		require.Contains(t, resp.FallbackReason, "no completed full baseline")
	})

	t.Run("incremental with a resolved baseline classifies against it", func(t *testing.T) {
		resp := request[ingestResponse](t, http.MethodPost, "/api/v1/reports", key,
			ingestBodyWith(t, slug, "high-new.sarif.json", map[string]any{
				"scan_mode":     "incremental",
				"commit_sha":    "4444444444444444444444444444444444444444",
				"base_revision": baseSHA,
				"changed_files": []string{"src/repository.go"},
				"scanner":       "semgrep",
			}), http.StatusCreated)
		require.Equal(t, "incremental", resp.ScanMode,
			"a completed full baseline at the base revision must keep the mode incremental")
		require.Empty(t, resp.FallbackReason)
		require.Equal(t, 2, resp.TotalFindings)
		require.Equal(t, 1, resp.IntroducedCount,
			"the new rule is introduced by this change")
		require.Equal(t, 1, resp.PreExistingCount,
			"the baseline high re-reported against the baseline stays pre-existing")
		require.True(t, resp.ThresholdBreached,
			"the introduced high must still block the full gate after an incremental scan")
	})
}
