//go:build e2e

package e2e

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestE2E_IntroducedGateScopesToChange pins ADR-022's core promise through
// the public API and the CLI: a PR report that only re-reports baseline debt
// passes the change gate while the full gate keeps blocking, and a PR that
// introduces a blocking finding fails only the change gate. Classification
// runs against a real baseline resolved from base_revision.
func TestE2E_IntroducedGateScopesToChange(t *testing.T) {
	slug := newProject(t, "intro-api")
	key := mintKey(t, slug)

	baseline := request[ingestResponse](t, http.MethodPost, "/api/v1/reports", key,
		ingestBodyWith(t, slug, "high-medium.sarif.json", map[string]any{
			"commit_sha": baseSHA,
		}), http.StatusCreated)
	require.Equal(t, 2, baseline.TotalFindings)
	require.Equal(t, "full", baseline.ScanMode)
	require.True(t, baseline.ThresholdBreached,
		"the baseline itself must breach the full gate at the default floor")

	t.Run("a pr introducing a blocking finding fails the change gate", func(t *testing.T) {
		pr := request[ingestResponse](t, http.MethodPost, "/api/v1/reports", key,
			ingestBodyWith(t, slug, "high-new.sarif.json", map[string]any{
				"commit_sha":           "2222222222222222222222222222222222222222",
				"base_revision":        baseSHA,
				"gate_introduced_only": true,
			}), http.StatusCreated)
		require.Equal(t, 2, pr.TotalFindings)
		require.Equal(t, "full", pr.ScanMode)
		require.True(t, pr.ThresholdBreached,
			"the newly introduced high must fail the change gate")
		require.Equal(t, 1, pr.IntroducedCount, "only the new rule is introduced")
		require.Equal(t, 1, pr.PreExistingCount, "the baseline high re-reported as pre-existing")

		gs := getGate(t, slug, "introduced_only=1&report_id="+pr.ReportID)
		require.True(t, gs.ThresholdBreached)
		require.EqualValues(t, 1, gs.BlockingCount,
			"the change gate blocks exactly the introduced finding")

		var introducedID string
		for _, f := range listFindings(t, slug) {
			if f.CurrentTitle == "SQL injection in user query" {
				introducedID = f.ID
			}
		}
		require.NotEmpty(t, introducedID, "the introduced finding must be persisted")
		require.Contains(t, gs.BlockedBy, introducedID)

		full := getGate(t, slug, "")
		require.True(t, full.ThresholdBreached,
			"the full gate must keep blocking regardless of change scoping")
		require.EqualValues(t, 2, full.BlockingCount,
			"both the baseline high and the introduced high block the full gate")

		stdout, stderr, exit := runBin(t, cliBin,
			[]string{"API_URL=" + baseURL, "API_KEY=" + key},
			"gate", "check", "--project", slug, "--introduced-only",
			"--report-id", pr.ReportID, "--format", "json")
		require.Equal(t, 1, exit, "introduced gate breach must exit 1; stderr:\n%s", stderr)
		var igs gateStatus
		require.NoError(t, json.Unmarshal([]byte(stdout), &igs), "stdout: %s", stdout)
		require.True(t, igs.ThresholdBreached)
		require.EqualValues(t, 1, igs.BlockingCount)
	})

	t.Run("a pr re-reporting only baseline debt passes the change gate", func(t *testing.T) {
		pr := request[ingestResponse](t, http.MethodPost, "/api/v1/reports", key,
			ingestBodyWith(t, slug, "high.sarif.json", map[string]any{
				"commit_sha":           "3333333333333333333333333333333333333333",
				"base_revision":        baseSHA,
				"gate_introduced_only": true,
			}), http.StatusCreated)
		require.Equal(t, 1, pr.TotalFindings)
		require.False(t, pr.ThresholdBreached,
			"pre-existing baseline debt must not fail the change gate (ADR-022)")
		require.Equal(t, 0, pr.IntroducedCount)
		require.Equal(t, 1, pr.PreExistingCount)

		gs := getGate(t, slug, "introduced_only=1&report_id="+pr.ReportID)
		require.False(t, gs.ThresholdBreached)
		require.Zero(t, gs.BlockingCount)

		full := getGate(t, slug, "")
		require.True(t, full.ThresholdBreached,
			"the same debt must still block the full gate")
		require.EqualValues(t, 2, full.BlockingCount)

		stdout, stderr, exit := runBin(t, cliBin,
			[]string{"API_URL=" + baseURL, "API_KEY=" + key},
			"gate", "check", "--project", slug, "--introduced-only",
			"--report-id", pr.ReportID)
		require.Equal(t, 0, exit, "pre-existing-only report must exit 0; stderr:\n%s", stderr)
		require.Contains(t, stdout, "gate PASSED: no blocking findings")

		fullOut, stderr, exit := runBin(t, cliBin,
			[]string{"API_URL=" + baseURL, "API_KEY=" + key},
			"gate", "check", "--project", slug)
		require.Equal(t, 1, exit, "the full gate must still fail on the debt; stderr:\n%s", stderr)
		require.Contains(t, fullOut, "gate FAILED: 2 blocking finding(s)")
	})

	t.Run("change gate evaluation requires a report id", func(t *testing.T) {
		status, raw := doJSON(t, http.MethodGet,
			"/api/v1/projects/"+slug+"/gate?introduced_only=1", adminToken, nil)
		require.Equal(t, http.StatusBadRequest, status)
		require.Contains(t, string(raw), "missing_report_id")

		_, stderr, exit := runBin(t, cliBin,
			[]string{"API_URL=" + baseURL, "API_KEY=" + key},
			"gate", "check", "--project", slug, "--introduced-only")
		require.Equal(t, 2, exit)
		require.Contains(t, stderr, "--report-id is required with --introduced-only")
	})
}

// TestE2E_AdapterIntroducedGateVerdicts exercises the adapter binary exactly
// as a PR pipeline would with -introduced-only: baseline debt on the target
// branch never fails the build, an introduced blocking finding does, and the
// stderr output partitions the two verdicts.
func TestE2E_AdapterIntroducedGateVerdicts(t *testing.T) {
	slug := newProject(t, "intro-adapter")
	key := mintKey(t, slug)

	request[ingestResponse](t, http.MethodPost, "/api/v1/reports", key,
		ingestBodyWith(t, slug, "high-medium.sarif.json", map[string]any{
			"commit_sha": baseSHA,
		}), http.StatusCreated)

	t.Run("pre-existing debt passes with a debt banner", func(t *testing.T) {
		_, stderr, exit := runBin(t, adapterBin,
			[]string{"API_URL=" + baseURL, "API_KEY=" + key},
			"-project", slug, "-tool", "sarif",
			"-file", absFixture(t, "high.sarif.json"),
			"-introduced-only", "-base-ref", baseSHA)
		require.Equal(t, 0, exit, "baseline debt must not fail the PR gate; stderr:\n%s", stderr)
		require.Contains(t, stderr, "SPECHT SECURITY GATE: PASSED")
		require.Contains(t, stderr, "PRE-EXISTING DEBT IN BASELINE: 1")
	})

	t.Run("an introduced blocking finding fails the build", func(t *testing.T) {
		_, stderr, exit := runBin(t, adapterBin,
			[]string{"API_URL=" + baseURL, "API_KEY=" + key},
			"-project", slug, "-tool", "sarif",
			"-file", absFixture(t, "high-new.sarif.json"),
			"-introduced-only", "-base-ref", baseSHA)
		require.Equal(t, 1, exit, "an introduced high must fail the PR gate; stderr:\n%s", stderr)
		require.Contains(t, stderr, "SPECHT SECURITY GATE: FAILED")
		require.Contains(t, stderr, "NEW BLOCKING FINDINGS INTRODUCED IN THIS CHANGE: 1")
	})
}
