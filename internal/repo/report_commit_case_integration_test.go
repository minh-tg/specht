//go:build integration

package repo

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/port"
)

func TestReportCommitFilterAcceptsMixedCase(t *testing.T) {
	s, cleanup := newScopeSeverityScenario(t)
	defer cleanup()
	id := s.report(t, "main", "high", 3, 0)
	_, err := s.pool.Exec(s.ctx, `UPDATE reports SET commit_sha='aabbccdd', branch='Main' WHERE id=$1`, id)
	require.NoError(t, err)
	for _, commit := range []string{"aabbccdd", "AABBCCDD", "AaBbCcDd"} {
		for _, prefix := range []bool{false, true} {
			rows, err := s.stores.Reports.ListByProject(s.ctx, s.projectID, port.ReportFilter{CommitSha: commit, CommitPrefix: prefix, Branch: "Main"}, 10, 0)
			require.NoError(t, err)
			require.Len(t, rows, 1, "commit=%s prefix=%t", commit, prefix)
		}
	}
	rows, err := s.stores.Reports.ListByProject(s.ctx, s.projectID, port.ReportFilter{CommitSha: "AABBCCDD", Branch: "main"}, 10, 0)
	require.NoError(t, err)
	require.Empty(t, rows, "branch names remain case-sensitive")
}
