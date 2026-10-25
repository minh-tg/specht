//go:build integration

package repo

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/domain"
	"github.com/minh-tg/specht/internal/port"
)

// examinedScenario adds rule and file dimensions to the scenario finding and
// records scans of it that are not complete, as a SARIF or Checkov report is.
func examinedScenario(t *testing.T) (*scopeSeverityScenario, func()) {
	t.Helper()
	s, cleanup := newScopeSeverityScenario(t)
	_, err := s.pool.Exec(s.ctx, `INSERT INTO finding_dimensions (finding_id, dim_key, dim_value) VALUES ($1, 'rule_id', 'go/sql-injection'), ($1, 'file', 'a/b.go')`, s.findingID)
	require.NoError(t, err)
	return s, cleanup
}

func (s *scopeSeverityScenario) keyedReport(t *testing.T, scope, hash, completeness string, kinds, keys []string) string {
	t.Helper()
	r, err := s.stores.Reports.Create(s.ctx, port.CreateReportInput{
		ProjectID: s.projectID, ToolName: "sarif", ScanType: "filesystem", ScanScopeHash: scope,
		ScanScope: []byte(`{}`), RawReportHash: hash, ScanMode: "full", ScanCompleteness: completeness,
		CoveredFindingKinds: kinds, ExaminedKeys: keys,
	})
	require.NoError(t, err)
	_, err = s.stores.Reports.UpdateStatus(s.ctx, r.ID, s.projectID, "completed", 0, nil)
	require.NoError(t, err)
	return r.ID
}

func TestReportExaminedFindingMatchesPerFinding(t *testing.T) {
	s, cleanup := examinedScenario(t)
	defer cleanup()
	rule := domain.ExaminedRule("sca", "go/sql-injection")
	cases := []struct {
		name         string
		completeness string
		kinds, keys  []string
		want         bool
	}{
		{"rule listed", "unknown", nil, []string{rule}, true},
		{"other rule listed", "unknown", nil, []string{domain.ExaminedRule("sca", "go/xss")}, false},
		{"rule of another kind", "unknown", nil, []string{domain.ExaminedRule("iac", "go/sql-injection")}, false},
		{"fingerprint listed", "unknown", nil, []string{domain.ExaminedFingerprint("shared")}, true},
		{"other fingerprint listed", "unknown", nil, []string{domain.ExaminedFingerprint("other")}, false},
		{"rule and file listed", "unknown", nil, []string{rule, domain.ExaminedFilesScope, domain.ExaminedFile("a/b.go")}, true},
		{"rule listed, file not scanned", "unknown", nil, []string{rule, domain.ExaminedFilesScope, domain.ExaminedFile("c/d.go")}, false},
		{"file listed without a rule", "unknown", nil, []string{domain.ExaminedFilesScope, domain.ExaminedFile("a/b.go")}, false},
		{"partial report proves nothing", "partial", nil, []string{rule}, false},
		{"no keys", "unknown", nil, nil, false},
		{"complete report covering the kind", "complete", []string{"sca"}, nil, true},
		{"unknown report covering the kind", "unknown", []string{"sca"}, nil, false},
		{"complete report covering another kind", "complete", []string{"iac"}, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var kinds, keys any
			if tc.kinds != nil {
				kinds = tc.kinds
			}
			if tc.keys != nil {
				keys = tc.keys
			}
			var got bool
			require.NoError(t, s.pool.QueryRow(s.ctx,
				`SELECT report_examined_finding($1, $2::text[], $3::text[], $4::uuid, 'sca', 'shared')`,
				tc.completeness, kinds, keys, s.findingID).Scan(&got))
			require.Equal(t, tc.want, got)
		})
	}
}

func TestExaminedKeysCloseOnlyTheFindingsTheyName(t *testing.T) {
	for _, tc := range []struct {
		name string
		keys []string
		want string
	}{
		{"rule listed", []string{domain.ExaminedRule("sca", "go/sql-injection")}, "fixed"},
		{"other rule listed", []string{domain.ExaminedRule("sca", "go/xss")}, "open"},
		{"no proof", nil, "open"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, cleanup := examinedScenario(t)
			defer cleanup()
			s.report(t, "main", "high", 3, time.Hour)
			clean := s.keyedReport(t, "main", "clean", "unknown", nil, tc.keys)
			fixed, err := s.stores.Findings.MarkAbsentFindingsFixed(s.ctx, s.projectID, "main", clean)
			require.NoError(t, err)
			require.Equal(t, tc.want, s.finding(t).State)
			if tc.want == "fixed" {
				require.Len(t, fixed, 1)
				require.Empty(t, s.scopes(t))
			} else {
				require.Empty(t, fixed)
				require.Len(t, s.scopes(t), 1)
			}
		})
	}
}

// A report delete restores the newest evidence of a scope, but not past a
// clean scan. A clean scan that proved the finding examined counts; one that
// proved nothing does not.
func TestReportDeleteHonoursExaminedKeysAsACleanScan(t *testing.T) {
	for _, tc := range []struct {
		name       string
		keys       []string
		wantScopes int
	}{
		{"clean scan proved the finding", []string{domain.ExaminedRule("sca", "go/sql-injection")}, 0},
		{"clean scan proved nothing", nil, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, cleanup := examinedScenario(t)
			defer cleanup()
			s.report(t, "main", "high", 3, 3*time.Hour)
			s.keyedReport(t, "main", "clean", "unknown", nil, tc.keys)
			// The clean scan only retires the scope row when it proves the
			// finding examined, which MarkAbsentFindingsFixed decides.
			clean := s.latestReport(t)
			_, err := s.stores.Findings.MarkAbsentFindingsFixed(s.ctx, s.projectID, "main", clean)
			require.NoError(t, err)
			newer := s.report(t, "main", "critical", 4, time.Minute)
			s.deleteReport(t, newer)
			require.Len(t, s.scopes(t), tc.wantScopes)
		})
	}
}

func (s *scopeSeverityScenario) latestReport(t *testing.T) string {
	t.Helper()
	var id string
	require.NoError(t, s.pool.QueryRow(s.ctx, `SELECT id::text FROM reports WHERE raw_report_hash = 'clean'`).Scan(&id))
	return id
}
