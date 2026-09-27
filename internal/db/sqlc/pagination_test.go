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
		{"reports", listReportsByProject, "ORDER BY created_at DESC, id DESC"},
		{"finding events", listFindingEvents, "ORDER BY created_at DESC, id DESC"},
		{"evidence", listEvidenceByFinding, "ORDER BY created_at DESC, id DESC"},
		{"active waivers", listActiveWaivers, "ORDER BY created_at DESC, id DESC"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !strings.Contains(tt.query, tt.order) {
				t.Fatalf("query order is not stable: missing %q", tt.order)
			}
		})
	}
}
