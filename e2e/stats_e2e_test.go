//go:build e2e

package e2e

import (
	"context"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// The project statistics and aging read surfaces: aggregate counts that
// track real ingest, triage, and waivers, and an SLA-bucketed age snapshot.

type severityCount struct {
	Severity      string `json:"severity"`
	Count         int32  `json:"count"`
	BlockingCount int32  `json:"blocking_count"`
}

type analysisStateCount struct {
	State string `json:"state"`
	Count int32  `json:"count"`
}

type latestReport struct {
	ID       string `json:"id"`
	ToolName string `json:"tool_name"`
	Status   string `json:"status"`
}

type statsResponse struct {
	TotalFindings   int32                `json:"total_findings"`
	BlockingCount   int32                `json:"blocking_count"`
	WaiverCount     int32                `json:"waiver_count"`
	ReportCount     int32                `json:"report_count"`
	BySeverity      []severityCount      `json:"by_severity"`
	ByAnalysisState []analysisStateCount `json:"by_analysis_state"`
	LatestReport    *latestReport        `json:"latest_report"`
}

type agingBucket struct {
	Bucket  string `json:"bucket"`
	Count   int32  `json:"count"`
	Overdue int32  `json:"overdue"`
}

type overdueFinding struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	AgeDays  int32  `json:"age_days"`
	SLADays  int32  `json:"sla_days"`
}

type weeklyNew struct {
	Week  string `json:"week"`
	Count int32  `json:"count"`
}

type agingResponse struct {
	Buckets      []agingBucket    `json:"buckets"`
	OverdueTotal int32            `json:"overdue_total"`
	Overdue      []overdueFinding `json:"overdue"`
	Reopened     int32            `json:"reopened"`
	NewPerWeek   []weeklyNew      `json:"new_per_week"`
}

func readStats(t *testing.T, slug, token string, wantStatus int) statsResponse {
	t.Helper()
	return request[statsResponse](t, http.MethodGet,
		"/api/v1/projects/"+slug+"/stats", token, nil, wantStatus)
}

func readAging(t *testing.T, slug, token string, wantStatus int) agingResponse {
	t.Helper()
	return request[agingResponse](t, http.MethodGet,
		"/api/v1/projects/"+slug+"/aging", token, nil, wantStatus)
}

// bucketCount returns one bucket's count from an aging snapshot.
func bucketCount(aging agingResponse, bucket string) int32 {
	for _, b := range aging.Buckets {
		if b.Bucket == bucket {
			return b.Count
		}
	}
	return -1
}

// weeklyTotal sums the trailing-window counts.
func weeklyTotal(aging agingResponse) int32 {
	var total int32
	for _, w := range aging.NewPerWeek {
		total += w.Count
	}
	return total
}

// backdateProjectFindings ages every finding in a project so the SLA view
// can observe it. No API writes first_seen_at, so the test arranges that
// precondition directly in the test database; the aging computation itself
// still runs over real rows through the real endpoint.
func backdateProjectFindings(t *testing.T, slug string, days int) {
	t.Helper()
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	tag, err := pool.Exec(ctx,
		`UPDATE findings
		    SET first_seen_at = now() - make_interval(days => $2)
		  WHERE project_id = (SELECT id FROM projects WHERE slug = $1)`, slug, days)
	require.NoError(t, err)
	require.NotZero(t, tag.RowsAffected(), "the project's findings must exist")
}

// TestE2E_ProjectStatsAndAging walks the two aggregate read surfaces: the
// roll-up tracks ingest, triage, and waiver state, and the aging snapshot
// buckets findings by age with their SLA position.
func TestE2E_ProjectStatsAndAging(t *testing.T) {
	slug := newProject(t, "stats")
	key := mintKey(t, slug)

	t.Run("an empty project reports zeroed aggregates", func(t *testing.T) {
		stats := readStats(t, slug, adminToken, http.StatusOK)
		require.Zero(t, stats.TotalFindings)
		require.Zero(t, stats.BlockingCount)
		require.Zero(t, stats.WaiverCount)
		require.Zero(t, stats.ReportCount)
		require.Empty(t, stats.BySeverity)
		require.Empty(t, stats.ByAnalysisState)
		require.Nil(t, stats.LatestReport, "a project with no reports claims no latest one")

		aging := readAging(t, slug, adminToken, http.StatusOK)
		var names []string
		for _, b := range aging.Buckets {
			names = append(names, b.Bucket)
			require.Zero(t, b.Count)
			require.Zero(t, b.Overdue)
		}
		require.Equal(t, []string{"new", "aging", "stale", "debt"}, names,
			"the buckets are always present, and in age order")
		require.Zero(t, aging.OverdueTotal)
		require.Empty(t, aging.Overdue)
		require.Zero(t, aging.Reopened)
		require.Len(t, aging.NewPerWeek, 12, "the trend window is always twelve weeks")
		require.Zero(t, weeklyTotal(aging))
	})

	t.Run("ingest moves the aggregates", func(t *testing.T) {
		// One report only, so "latest" is unambiguous: the SARIF fixture
		// carries one high and one medium finding.
		resp := ingestFixture(t, slug, key, "high-medium.sarif.json")
		require.Equal(t, 2, resp.TotalFindings)

		stats := readStats(t, slug, adminToken, http.StatusOK)
		require.EqualValues(t, 2, stats.TotalFindings)
		require.EqualValues(t, 2, stats.BlockingCount,
			"both findings block until an analyst decides otherwise")
		require.EqualValues(t, 1, stats.ReportCount)
		require.Zero(t, stats.WaiverCount)

		bySeverity := map[string]severityCount{}
		for _, s := range stats.BySeverity {
			bySeverity[s.Severity] = s
		}
		require.Len(t, bySeverity, 2)
		require.EqualValues(t, 1, bySeverity["high"].Count)
		require.EqualValues(t, 1, bySeverity["high"].BlockingCount)
		require.EqualValues(t, 1, bySeverity["medium"].Count)
		require.EqualValues(t, 1, bySeverity["medium"].BlockingCount)

		require.Equal(t, []analysisStateCount{{State: "unanalyzed", Count: 2}}, stats.ByAnalysisState,
			"fresh findings are untriaged and bucket under unanalyzed")

		require.NotNil(t, stats.LatestReport)
		require.Equal(t, "sarif", stats.LatestReport.ToolName)
		require.Equal(t, "completed", stats.LatestReport.Status)
		require.Equal(t, resp.ReportID, stats.LatestReport.ID)
	})

	t.Run("fresh findings land in the newest bucket, not overdue", func(t *testing.T) {
		aging := readAging(t, slug, adminToken, http.StatusOK)
		require.EqualValues(t, 2, bucketCount(aging, "new"))
		require.Zero(t, bucketCount(aging, "aging"))
		require.Zero(t, bucketCount(aging, "stale"))
		require.Zero(t, bucketCount(aging, "debt"))
		require.Zero(t, aging.OverdueTotal, "a finding seen today has not breached its SLA")
		require.Empty(t, aging.Overdue)
		require.EqualValues(t, 2, weeklyTotal(aging))
	})

	t.Run("triage moves the blocking roll-up", func(t *testing.T) {
		high := highFinding(t, slug)
		request[triageOutput](t, http.MethodPatch, "/api/v1/findings/"+high.ID, adminToken,
			map[string]any{"analysis_state": "false_positive", "reason": "test-only path"},
			http.StatusOK)

		stats := readStats(t, slug, adminToken, http.StatusOK)
		require.EqualValues(t, 2, stats.TotalFindings, "deciding a finding never removes it")
		require.EqualValues(t, 1, stats.BlockingCount,
			"an ignoring analysis state leaves the roll-up")
		require.Equal(t, []analysisStateCount{
			{State: "false_positive", Count: 1},
			{State: "unanalyzed", Count: 1},
		}, stats.ByAnalysisState, "triage moves one finding out of the unanalyzed bucket")
		for _, s := range stats.BySeverity {
			if s.Severity == "high" {
				require.Zero(t, s.BlockingCount)
			}
			if s.Severity == "medium" {
				require.EqualValues(t, 1, s.BlockingCount)
			}
		}
	})

	t.Run("only enabled waivers count", func(t *testing.T) {
		waiver := createWaiver(t, slug, "stats-waiver-"+randomHex(3), highFinding(t, slug).ID, "")
		require.EqualValues(t, 1, readStats(t, slug, adminToken, http.StatusOK).WaiverCount)

		disabled := request[waiverDetail](t, http.MethodPost,
			"/api/v1/projects/"+slug+"/waivers/"+waiver.ID+"/toggle", adminToken, nil, http.StatusOK)
		require.False(t, disabled.Enabled)
		require.Zero(t, readStats(t, slug, adminToken, http.StatusOK).WaiverCount,
			"a disabled waiver is not counted")

		reenabled := request[waiverDetail](t, http.MethodPost,
			"/api/v1/projects/"+slug+"/waivers/"+waiver.ID+"/toggle", adminToken, nil, http.StatusOK)
		require.True(t, reenabled.Enabled)
		require.EqualValues(t, 1, readStats(t, slug, adminToken, http.StatusOK).WaiverCount)
	})

	t.Run("aging assigns buckets and SLA from severity and age", func(t *testing.T) {
		// A second project so the 40-day backdating stays isolated. At 40
		// days the high finding (30-day SLA) is overdue inside the stale
		// bucket, while the medium finding (90-day SLA) is not.
		aged := newProject(t, "aging-overdue")
		ingestFixture(t, aged, mintKey(t, aged), "high-medium.sarif.json")
		backdateProjectFindings(t, aged, 40)

		aging := readAging(t, aged, adminToken, http.StatusOK)
		require.EqualValues(t, 2, bucketCount(aging, "stale"))
		require.Zero(t, bucketCount(aging, "new"))
		require.Zero(t, bucketCount(aging, "debt"))
		require.EqualValues(t, 1, aging.OverdueTotal,
			"only the finding past its severity's SLA counts as overdue")
		require.Len(t, aging.Overdue, 1)

		overdue := aging.Overdue[0]
		require.Equal(t, "high", overdue.Severity)
		require.EqualValues(t, 40, overdue.AgeDays)
		require.EqualValues(t, 30, overdue.SLADays, "the high-severity SLA is 30 days")
		require.NotEmpty(t, overdue.Title)
		require.Zero(t, aging.Reopened)

		require.EqualValues(t, 2, weeklyTotal(aging),
			"the backdated findings stay inside the twelve-week trend window")
		require.Zero(t, aging.NewPerWeek[len(aging.NewPerWeek)-1].Count,
			"nothing was first seen in the current week")
	})

	t.Run("both surfaces enforce project access", func(t *testing.T) {
		viewerToken := login(t, "e2e-viewer@example.com", adminPass)
		for _, path := range []string{"stats", "aging"} {
			status, raw := doJSON(t, http.MethodGet, "/api/v1/projects/"+slug+"/"+path, viewerToken, nil)
			require.Equal(t, http.StatusForbidden, status)
			require.Equal(t, "project_access_denied", errorCode(t, raw))

			status, raw = doJSON(t, http.MethodGet, "/api/v1/projects/e2e-missing-"+randomHex(4)+"/"+path, adminToken, nil)
			require.Equal(t, http.StatusNotFound, status)
			require.Equal(t, "not_found", errorCode(t, raw))
		}

		// The minted project key reads its own project's roll-up.
		require.EqualValues(t, 2, readStats(t, slug, key, http.StatusOK).TotalFindings)
		require.Len(t, readAging(t, slug, key, http.StatusOK).Buckets, 4)
	})
}
