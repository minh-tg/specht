//go:build integration

package repo

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// changeBranches reads the rule the project verdict and the findings filter share.
func (s *scopeSeverityScenario) changeBranches(t *testing.T) []string {
	t.Helper()
	var branches []string
	require.NoError(t, s.pool.QueryRow(s.ctx,
		`SELECT finding_change_branches($1::uuid)`, s.findingID).Scan(&branches))
	return branches
}

// onBranch records one scan of the finding on a branch. The scenario's report
// helper takes a scope, not a branch.
func (s *scopeSeverityScenario) onBranch(t *testing.T, branch string, age time.Duration) string {
	t.Helper()
	id := s.report(t, "scope-"+branch, "high", 3, age)
	_, err := s.pool.Exec(s.ctx, `UPDATE reports SET branch = NULLIF($2, '') WHERE id = $1`, id, branch)
	require.NoError(t, err)
	return id
}

func TestFindingChangeBranches(t *testing.T) {
	asChange := func(t *testing.T, s *scopeSeverityScenario, reportID string) {
		t.Helper()
		_, err := s.pool.Exec(s.ctx, `UPDATE reports SET base_revision = 'main' WHERE id = $1`, reportID)
		require.NoError(t, err)
	}

	t.Run("a branch that named another base is a change", func(t *testing.T) {
		s, cleanup := newScopeSeverityScenario(t)
		defer cleanup()
		asChange(t, s, s.onBranch(t, "feat/x", 0))
		require.Equal(t, []string{"feat/x"}, s.changeBranches(t))
	})

	t.Run("a branch that never named a base counts without a default branch", func(t *testing.T) {
		s, cleanup := newScopeSeverityScenario(t)
		defer cleanup()
		s.onBranch(t, "main", 0)
		require.Empty(t, s.changeBranches(t))
	})

	t.Run("one sighting on the default branch is enough to count", func(t *testing.T) {
		s, cleanup := newScopeSeverityScenario(t)
		defer cleanup()
		asChange(t, s, s.onBranch(t, "feat/x", time.Hour))
		s.onBranch(t, "main", 0)
		require.Empty(t, s.changeBranches(t))
	})

	t.Run("every change branch is named", func(t *testing.T) {
		s, cleanup := newScopeSeverityScenario(t)
		defer cleanup()
		asChange(t, s, s.onBranch(t, "feat/b", time.Hour))
		asChange(t, s, s.onBranch(t, "feat/a", 0))
		require.Equal(t, []string{"feat/a", "feat/b"}, s.changeBranches(t))
	})

	t.Run("a set default branch makes every other branch a change", func(t *testing.T) {
		s, cleanup := newScopeSeverityScenario(t)
		defer cleanup()
		s.onBranch(t, "push-only", 0)
		_, err := s.pool.Exec(s.ctx, `UPDATE projects SET default_branch = 'main' WHERE id = $1`, s.projectID)
		require.NoError(t, err)
		require.Equal(t, []string{"push-only"}, s.changeBranches(t))
	})

	t.Run("the default branch sent with another base still counts", func(t *testing.T) {
		s, cleanup := newScopeSeverityScenario(t)
		defer cleanup()
		_, err := s.pool.Exec(s.ctx, `UPDATE projects SET default_branch = 'main' WHERE id = $1`, s.projectID)
		require.NoError(t, err)
		id := s.onBranch(t, "main", 0)
		_, err = s.pool.Exec(s.ctx, `UPDATE reports SET base_revision = 'release' WHERE id = $1`, id)
		require.NoError(t, err)
		require.Empty(t, s.changeBranches(t))
	})

	t.Run("one report with a base cannot take a long-lived branch out", func(t *testing.T) {
		s, cleanup := newScopeSeverityScenario(t)
		defer cleanup()
		s.onBranch(t, "main", time.Hour)
		// A pull request from main to release, or a base spelled origin/main.
		other := s.report(t, "scope-main-release", "low", 1, time.Minute)
		_, err := s.pool.Exec(s.ctx, `UPDATE reports SET branch = 'main', base_revision = 'release' WHERE id = $1`, other)
		require.NoError(t, err)
		require.Empty(t, s.changeBranches(t))
	})

	t.Run("a report without a branch counts", func(t *testing.T) {
		s, cleanup := newScopeSeverityScenario(t)
		defer cleanup()
		_, err := s.pool.Exec(s.ctx, `UPDATE projects SET default_branch = 'main' WHERE id = $1`, s.projectID)
		require.NoError(t, err)
		s.onBranch(t, "", 0)
		require.Empty(t, s.changeBranches(t))
	})

	t.Run("a sighting whose report was deleted counts", func(t *testing.T) {
		s, cleanup := newScopeSeverityScenario(t)
		defer cleanup()
		asChange(t, s, s.onBranch(t, "feat/x", 0))
		_, err := s.pool.Exec(s.ctx, `UPDATE finding_scope_severities SET report_id = NULL WHERE finding_id = $1`, s.findingID)
		require.NoError(t, err)
		require.Empty(t, s.changeBranches(t))
	})

	t.Run("a finding with no sightings counts", func(t *testing.T) {
		s, cleanup := newScopeSeverityScenario(t)
		defer cleanup()
		require.Empty(t, s.changeBranches(t))
	})
}
