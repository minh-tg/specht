//go:build e2e

package e2e

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// prCheckConclusion reads the pull request check conclusion for a commit,
// scoped to one report when reportID is set.
func prCheckConclusion(t *testing.T, slug, key, commit, reportID string) string {
	t.Helper()
	path := "/api/v1/projects/" + slug + "/pr-check?commit=" + commit
	if reportID != "" {
		path += "&report_id=" + reportID
	}
	status, raw := doJSON(t, http.MethodGet, path, key, nil)
	require.Equal(t, http.StatusOK, status, "%s", raw)
	var check struct {
		Conclusion string `json:"conclusion"`
	}
	require.NoError(t, json.Unmarshal(raw, &check))
	return check.Conclusion
}

// TestE2E_BaseRevisionCannotVouchForTheBranchsOwnFindings pins that the
// uploader's choice of base_revision cannot turn a branch's blockers into
// pre-existing debt. A report of the branch itself, by name or by an earlier
// commit, and a report of another change branch are not baselines; the
// branch keeps what it introduced while it still has it.
func TestE2E_BaseRevisionCannotVouchForTheBranchsOwnFindings(t *testing.T) {
	t.Run("the branch names itself as base", func(t *testing.T) {
		slug := newProject(t, "base-self")
		key := mintKey(t, slug)
		first := carryPush(t, slug, key, "high-new.sarif.json", "feat/x",
			"d100000000000000000000000000000000000001", "main")
		require.True(t, first.ThresholdBreached, "two highs new to the project block")
		require.Equal(t, 2, first.IntroducedCount)

		second := carryPush(t, slug, key, "high-new.sarif.json", "feat/x",
			"d100000000000000000000000000000000000002", "feat/x")
		require.Equal(t, 2, second.IntroducedCount)
		require.Zero(t, second.PreExistingCount)
		require.True(t, second.ThresholdBreached)
		require.Equal(t, "failure", prCheckConclusion(t, slug, key,
			"d100000000000000000000000000000000000002", second.ReportID))
	})

	t.Run("the branch names its own earlier commit as base", func(t *testing.T) {
		slug := newProject(t, "base-own-commit")
		key := mintKey(t, slug)
		first := carryPush(t, slug, key, "high-new.sarif.json", "feat/x",
			"d200000000000000000000000000000000000001", "main")
		require.True(t, first.ThresholdBreached)

		second := carryPush(t, slug, key, "high-new.sarif.json", "feat/x",
			"d200000000000000000000000000000000000002", "d200000000000000000000000000000000000001")
		require.Equal(t, 2, second.IntroducedCount)
		require.True(t, second.ThresholdBreached)
		require.Equal(t, "failure", prCheckConclusion(t, slug, key,
			"d200000000000000000000000000000000000002", ""))
	})

	t.Run("the branch names another blocked branch as base", func(t *testing.T) {
		slug := newProject(t, "base-other-branch")
		key := mintKey(t, slug)
		other := carryPush(t, slug, key, "high.sarif.json", "feat/other",
			"d300000000000000000000000000000000000001", "main")
		require.True(t, other.ThresholdBreached, "feat/other is blocked on its high")

		mine := carryPush(t, slug, key, "high-new.sarif.json", "feat/x",
			"d300000000000000000000000000000000000002", "main")
		require.True(t, mine.ThresholdBreached)
		require.Equal(t, 1, mine.IntroducedCount, "feat/x introduced E2E-NEW-003")

		// feat/other picks up the same finding, so its newest report holds both.
		carryPush(t, slug, key, "high-new.sarif.json", "feat/other",
			"d300000000000000000000000000000000000003", "main")

		laundered := carryPush(t, slug, key, "high-new.sarif.json", "feat/x",
			"d300000000000000000000000000000000000004", "feat/other")
		require.Equal(t, 1, laundered.IntroducedCount,
			"a change branch's report is no baseline: the finding feat/x introduced stays introduced")
		require.True(t, laundered.ThresholdBreached)
		require.Equal(t, "failure", prCheckConclusion(t, slug, key,
			"d300000000000000000000000000000000000004", laundered.ReportID))
	})

	t.Run("a scanned trunk stays the baseline", func(t *testing.T) {
		slug := newProject(t, "base-trunk")
		key := mintKey(t, slug)
		carryPush(t, slug, key, "high.sarif.json", "main", "d400000000000000000000000000000000000001", "")
		pr := carryPush(t, slug, key, "high-new.sarif.json", "feat/x",
			"d400000000000000000000000000000000000002", "main")
		require.Equal(t, 1, pr.IntroducedCount, "only the new rule is introduced against main")
		require.Equal(t, 1, pr.PreExistingCount, "main's high is pre-existing")
		byCommit := carryPush(t, slug, key, "high-new.sarif.json", "feat/y",
			"d400000000000000000000000000000000000003", "d400000000000000000000000000000000000001")
		require.Equal(t, 1, byCommit.IntroducedCount, "a main commit is a baseline too")
		require.Equal(t, 1, byCommit.PreExistingCount)
	})
}
