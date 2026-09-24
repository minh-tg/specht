//go:build e2e

package e2e

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestE2E_IngestFindingsAndGate covers the core business process: a CI
// pipeline's API key ingests a scanner report, findings land, and the
// deployment gate evaluates them at every severity floor boundary. It also
// pins tenant isolation: keys are bound to their own project, and neither
// viewer sessions nor ingest keys can cross write boundaries.
func TestE2E_IngestFindingsAndGate(t *testing.T) {
	slug := newProject(t, "ingest")
	key := mintKey(t, slug)

	t.Run("api key ingests a report", func(t *testing.T) {
		resp := ingestFixture(t, slug, key, "high-medium.sarif.json")
		require.Equal(t, 2, resp.TotalFindings)
		require.NotEmpty(t, resp.ReportID)
		require.Equal(t, "full", resp.ScanMode)
		require.True(t, resp.ThresholdBreached,
			"the default floor (high) must be breached by the high finding")
	})

	t.Run("identical report bytes are rejected as duplicate", func(t *testing.T) {
		status, raw := doJSON(t, http.MethodPost, "/api/v1/reports", key,
			ingestBody(t, slug, "high-medium.sarif.json"))
		require.Equal(t, http.StatusConflict, status)
		require.Contains(t, string(raw), "duplicate_report")
	})

	t.Run("findings are listed with expected severities and states", func(t *testing.T) {
		findings := listFindings(t, slug)
		require.Len(t, findings, 2)
		bySeverity := map[string]findingResponse{}
		for _, f := range findings {
			bySeverity[f.CurrentSeverity] = f
			require.Equal(t, "unanalyzed", f.AnalysisState)
			require.Equal(t, "block", f.GateEffect)
		}
		require.Contains(t, bySeverity, "high")
		require.Contains(t, bySeverity, "medium")

		highOnly := request[[]findingResponse](t, http.MethodGet,
			"/api/v1/projects/"+slug+"/findings?severity=high", adminToken, nil, http.StatusOK)
		require.Len(t, highOnly, 1)
	})

	t.Run("gate blocks at the default floor", func(t *testing.T) {
		gs := getGate(t, slug, "")
		require.True(t, gs.ThresholdBreached)
		require.EqualValues(t, 1, gs.BlockingCount, "only the high finding is at or above the floor")
		require.Len(t, gs.BlockedBy, 1)
		require.Equal(t, highFinding(t, slug).ID, gs.BlockedBy[0])
		require.Zero(t, gs.WaivedCount)
	})

	t.Run("gate reads work with the minted api key", func(t *testing.T) {
		// The adapter and CLI authenticate gate reads with the same
		// ingest-capable key they ingest with.
		gs := request[gateStatus](t, http.MethodGet, "/api/v1/projects/"+slug+"/gate", key, nil, http.StatusOK)
		require.True(t, gs.ThresholdBreached)
		require.EqualValues(t, 1, gs.BlockingCount)
	})

	t.Run("raising the floor above high unblocks the gate", func(t *testing.T) {
		gs := getGate(t, slug, "severity=critical")
		require.False(t, gs.ThresholdBreached, "no critical findings exist")
		require.Zero(t, gs.BlockingCount)
	})

	t.Run("lowering the floor to medium blocks both findings", func(t *testing.T) {
		gs := getGate(t, slug, "severity=medium")
		require.True(t, gs.ThresholdBreached)
		require.EqualValues(t, 2, gs.BlockingCount)
	})

	t.Run("listing high,critical blocks the high finding", func(t *testing.T) {
		// The documented adapter default "-severity high,critical" must
		// block every severity it names, not only the strictest one.
		gs := getGate(t, slug, "severity=high%2Ccritical")
		require.True(t, gs.ThresholdBreached,
			"naming high in the severity list must keep high findings blocking")
		require.EqualValues(t, 1, gs.BlockingCount)
	})

	t.Run("viewer sessions cannot read or write the project", func(t *testing.T) {
		viewerToken := login(t, "e2e-viewer@example.com", adminPass)
		status, _ := doJSON(t, http.MethodGet, "/api/v1/projects/"+slug+"/findings", viewerToken, nil)
		require.Equal(t, http.StatusForbidden, status)

		status, raw := doJSON(t, http.MethodPost, "/api/v1/reports", viewerToken,
			ingestBody(t, slug, "medium.sarif.json"))
		require.Equal(t, http.StatusForbidden, status)
		require.Contains(t, string(raw), "project_access_denied")
	})

	t.Run("api keys are bound to their own project", func(t *testing.T) {
		otherSlug := newProject(t, "ingest-other")
		status, raw := doJSON(t, http.MethodPost, "/api/v1/reports", key,
			ingestBody(t, otherSlug, "medium.sarif.json"))
		require.Equal(t, http.StatusForbidden, status)
		require.Contains(t, string(raw), "project_access_denied")
	})

	t.Run("api keys cannot mutate findings", func(t *testing.T) {
		findings := listFindings(t, slug)
		require.NotEmpty(t, findings)
		status, raw := doJSON(t, http.MethodPatch, "/api/v1/findings/"+findings[0].ID, key,
			map[string]string{"analysis_state": "false_positive", "reason": "key should not triage"})
		require.Equal(t, http.StatusForbidden, status)
		require.Contains(t, string(raw), "insufficient_scope")
	})
}
