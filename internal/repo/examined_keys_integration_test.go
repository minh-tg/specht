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

// examined asks report_examined_finding about the scenario finding, kind sca
// and fingerprint shared.
func (s *scopeSeverityScenario) examined(t *testing.T, completeness string, kinds, keys []string) bool {
	t.Helper()
	var k, ks any
	if kinds != nil {
		k = kinds
	}
	if keys != nil {
		ks = keys
	}
	var got bool
	require.NoError(t, s.pool.QueryRow(s.ctx,
		`SELECT report_examined_finding($1, $2::text[], $3::text[], $4::uuid, 'sca', 'shared')`,
		completeness, k, ks, s.findingID).Scan(&got))
	return got
}

func TestReportExaminedFindingMatchesPerFinding(t *testing.T) {
	s, cleanup := examinedScenario(t)
	defer cleanup()
	rule := domain.ExaminedRunRule(0, "sca", "go/sql-injection")
	file := domain.ExaminedRunFile(0, "a/b.go")
	cases := []struct {
		name         string
		completeness string
		kinds, keys  []string
		want         bool
	}{
		{"rule and file of one run", "unknown", nil, []string{rule, file}, true},
		{"rule without a file", "unknown", nil, []string{rule}, false},
		{"file without a rule", "unknown", nil, []string{file}, false},
		{"other rule listed", "unknown", nil, []string{domain.ExaminedRunRule(0, "sca", "go/xss"), file}, false},
		{"rule of another kind", "unknown", nil, []string{domain.ExaminedRunRule(0, "iac", "go/sql-injection"), file}, false},
		{"rule listed, file not scanned", "unknown", nil, []string{rule, domain.ExaminedRunFile(0, "c/d.go")}, false},
		{"rule and file of different runs", "unknown", nil, []string{
			rule, domain.ExaminedRunFile(0, "c/d.go"),
			domain.ExaminedRunRule(1, "sca", "go/xss"), domain.ExaminedRunFile(1, "a/b.go"),
		}, false},
		{"run 1 and run 10 are different runs", "unknown", nil, []string{
			domain.ExaminedRunRule(1, "sca", "go/sql-injection"), domain.ExaminedRunFile(10, "a/b.go"),
		}, false},
		{"rule and file of the second run", "unknown", nil, []string{
			domain.ExaminedRunRule(0, "sca", "go/xss"), domain.ExaminedRunFile(0, "c/d.go"),
			domain.ExaminedRunRule(1, "sca", "go/sql-injection"), domain.ExaminedRunFile(1, "a/b.go"),
		}, true},
		{"fingerprint listed", "unknown", nil, []string{domain.ExaminedFingerprint("shared")}, true},
		{"other fingerprint listed", "unknown", nil, []string{domain.ExaminedFingerprint("other")}, false},
		{"partial report proves nothing", "partial", nil, []string{rule, file}, false},
		{"no keys", "unknown", nil, nil, false},
		{"complete report covering the kind", "complete", []string{"sca"}, nil, true},
		{"unknown report covering the kind", "unknown", []string{"sca"}, nil, false},
		{"complete report covering another kind", "complete", []string{"iac"}, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, s.examined(t, tc.completeness, tc.kinds, tc.keys))
		})
	}
}

// A colon in a rule id or a path must not shift the run number the matcher
// reads, and a finding with no file is never proven by run keys.
func TestReportExaminedFindingRunKeyEdges(t *testing.T) {
	s, cleanup := examinedScenario(t)
	defer cleanup()
	_, err := s.pool.Exec(s.ctx, `UPDATE finding_dimensions SET dim_value = CASE dim_key WHEN 'rule_id' THEN 'a:b' ELSE 'c:/src/x.go' END WHERE finding_id = $1`, s.findingID)
	require.NoError(t, err)
	rule := domain.ExaminedRunRule(0, "sca", "a:b")
	file := domain.ExaminedRunFile(0, "c:/src/x.go")

	require.True(t, s.examined(t, "unknown", nil, []string{rule, file}))
	require.False(t, s.examined(t, "unknown", nil, []string{rule, domain.ExaminedRunFile(1, "c:/src/x.go")}))
	require.False(t, s.examined(t, "unknown", nil, []string{domain.ExaminedRunRule(0, "sca", "a"), file}))

	_, err = s.pool.Exec(s.ctx, `DELETE FROM finding_dimensions WHERE finding_id = $1 AND dim_key = 'file'`, s.findingID)
	require.NoError(t, err)
	require.False(t, s.examined(t, "unknown", nil, []string{rule, file}), "a finding with no file")
	require.True(t, s.examined(t, "unknown", nil, []string{domain.ExaminedFingerprint("shared")}))
}

func TestExaminedKeysCloseOnlyTheFindingsTheyName(t *testing.T) {
	for _, tc := range []struct {
		name string
		keys []string
		want string
	}{
		{"rule and file listed", []string{domain.ExaminedRunRule(0, "sca", "go/sql-injection"), domain.ExaminedRunFile(0, "a/b.go")}, "fixed"},
		{"rule listed by a run that never scanned the file", []string{
			domain.ExaminedRunRule(0, "sca", "go/sql-injection"), domain.ExaminedRunFile(0, "c/d.go"),
			domain.ExaminedRunRule(1, "sca", "go/xss"), domain.ExaminedRunFile(1, "a/b.go"),
		}, "open"},
		{"other rule listed", []string{domain.ExaminedRunRule(0, "sca", "go/xss"), domain.ExaminedRunFile(0, "a/b.go")}, "open"},
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
		{"clean scan proved the finding", []string{domain.ExaminedRunRule(0, "sca", "go/sql-injection"), domain.ExaminedRunFile(0, "a/b.go")}, 0},
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
