package sqlc

import (
	"strings"
	"testing"
)

func TestPaginatedQueriesUseStableTieBreakers(t *testing.T) {
	tests := []struct {
		name  string
		query string
		order string
	}{
		{"findings", listFindingsByProject, "ORDER BY f.current_severity_rank DESC, f.created_at DESC, f.id DESC"},
		{"latest finding context", getFindingContext, "ORDER BY fo.observed_at DESC, fo.id DESC"},
		{"latest finding display context", getFindingDisplayContext, "ORDER BY fo.observed_at DESC, fo.id DESC"},
		{"finding contexts by IDs", listFindingDisplayContextsByIDs, "ORDER BY fo.finding_id, fo.observed_at DESC, fo.id DESC"},
		{"gate candidates", listGateCandidates, "ORDER BY f.current_severity_rank DESC, f.created_at DESC, f.id DESC"},
		{"gate candidate latest occurrence", listGateCandidates, "ORDER BY fo.observed_at DESC, fo.id DESC"},
		{"gate candidate latest reachability", listGateCandidates, "ORDER BY ra.updated_at DESC, ra.id DESC"},
		{"introduced gate candidates", listIntroducedGateCandidates, "ORDER BY f.current_severity_rank DESC, f.created_at DESC, f.id DESC"},
		{"introduced gate latest occurrence", listIntroducedGateCandidates, "ORDER BY fo.observed_at DESC, fo.id DESC"},
		{"introduced gate latest reachability", listIntroducedGateCandidates, "ORDER BY ra.updated_at DESC, ra.id DESC"},
		{"findings introduced by report", listFindingsIntroducedByReport, "ORDER BY current_severity_rank DESC, created_at DESC, id DESC"},
		{"findings introduced by commit", listFindingsIntroducedByCommit, "ORDER BY current_severity_rank DESC, created_at DESC, id DESC"},
		{"reports", listReportsByProject, "ORDER BY created_at DESC, id DESC"},
		{"finding events", listFindingEvents, "ORDER BY created_at DESC, id DESC"},
		{"evidence", listEvidenceByFinding, "ORDER BY created_at DESC, id DESC"},
		{"active waivers", listActiveWaivers, "ORDER BY created_at DESC, id DESC"},
		{"waivers", listWaivers, "ORDER BY created_at DESC, id DESC"},
		{"projects", listProjects, "ORDER BY created_at DESC, id DESC"},
		{"projects by IDs", listProjectsByIDs, "ORDER BY created_at DESC, id DESC"},
		{"project members", listProjectMembers, "ORDER BY created_at ASC, user_id ASC"},
		{"aging findings", getAgingRows, "ORDER BY f.first_seen_at ASC, f.id ASC"},
		{"latest scanner report", latestCompletedReportByScanner, "ORDER BY created_at DESC, id DESC"},
		{"completed commit report", getCompletedReportByCommit, "ORDER BY created_at DESC, id DESC"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !strings.Contains(tt.query, tt.order) {
				t.Fatalf("query order is not stable: missing %q", tt.order)
			}
		})
	}
}
