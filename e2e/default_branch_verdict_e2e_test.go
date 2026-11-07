//go:build e2e

package e2e

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestE2E_ProjectVerdictAnswersForDefaultBranch pins that a scan of a change
// branch cannot move the default branch's verdict. It covers the open pull
// request, the abandoned branch that never scans again, and the merge.
func TestE2E_ProjectVerdictAnswersForDefaultBranch(t *testing.T) {
	const (
		mainFixture   = "high-medium.sarif.json"
		branchFixture = "high-new.sarif.json"
		newRuleTitle  = "SQL injection in user query"
		mainCommit    = "1111111111111111111111111111111111111111"
		branchCommit  = "2222222222222222222222222222222222222222"
	)
	slug := newProject(t, "verdict")
	key := mintKey(t, slug)
	send := func(fixture, commit, branch string, extra map[string]any) ingestResponse {
		t.Helper()
		body := map[string]any{"commit_sha": commit, "branch": branch}
		for k, v := range extra {
			body[k] = v
		}
		return request[ingestResponse](t, http.MethodPost, "/api/v1/reports", key,
			ingestBodyWith(t, slug, fixture, body), http.StatusCreated)
	}
	findingNamed := func(title string) findingResponse {
		t.Helper()
		for _, f := range listFindings(t, slug) {
			if f.CurrentTitle == title {
				return f
			}
		}
		t.Fatalf("no finding named %q", title)
		return findingResponse{}
	}

	send(mainFixture, mainCommit, "main", nil)
	require.EqualValues(t, 1, getGate(t, slug, "").BlockingCount, "the baseline high blocks main")

	pr := send(branchFixture, branchCommit, "feat/x", map[string]any{
		"base_revision": "main", "gate_introduced_only": true,
	})
	require.True(t, pr.ThresholdBreached, "the change itself is still judged on what it introduced")

	t.Run("an open pull request does not move main's verdict", func(t *testing.T) {
		require.EqualValues(t, 1, getGate(t, slug, "").BlockingCount)
		rescan := send(mainFixture, "1111111111111111111111111111111111111112", "main", nil)
		require.True(t, rescan.ThresholdBreached)
		require.EqualValues(t, 1, getGate(t, slug, "").BlockingCount,
			"an unchanged main rescan must report what main has, not what the branch has")
	})

	t.Run("the finding says where it was seen", func(t *testing.T) {
		f := findingNamed(newRuleTitle)
		require.Equal(t, []string{"feat/x"}, f.OnlyOnBranches)

		change := request[[]findingResponse](t, http.MethodGet,
			"/api/v1/projects/"+slug+"/findings?branch_scope=change", adminToken, nil, http.StatusOK)
		require.Len(t, change, 1)
		require.Equal(t, newRuleTitle, change[0].CurrentTitle)

		onDefault := request[[]findingResponse](t, http.MethodGet,
			"/api/v1/projects/"+slug+"/findings?branch_scope=default", adminToken, nil, http.StatusOK)
		for _, row := range onDefault {
			require.NotEqual(t, newRuleTitle, row.CurrentTitle)
		}

		stats := request[struct {
			OnlyOnChangeBranches int `json:"only_on_change_branches_count"`
		}](t, http.MethodGet, "/api/v1/projects/"+slug+"/stats", adminToken, nil, http.StatusOK)
		require.Equal(t, 1, stats.OnlyOnChangeBranches)
	})

	t.Run("a full gate run on the branch still counts the branch", func(t *testing.T) {
		gs := getGate(t, slug, "branch="+url.QueryEscape("feat/x"))
		require.True(t, gs.ThresholdBreached)
		require.EqualValues(t, 2, gs.BlockingCount, "main's high and the branch's own high")

		full := send(branchFixture, branchCommit, "feat/y", map[string]any{"base_revision": "main"})
		require.True(t, full.ThresholdBreached)
		require.EqualValues(t, 1, getGate(t, slug, "").BlockingCount)
	})

	t.Run("another branch's findings do not count on this branch", func(t *testing.T) {
		gs := getGate(t, slug, "branch="+url.QueryEscape("feat/other"))
		require.EqualValues(t, 1, gs.BlockingCount)
	})

	t.Run("an abandoned branch leaves main alone across rescans", func(t *testing.T) {
		send(mainFixture, "1111111111111111111111111111111111111113", "main", nil)
		send(mainFixture, "1111111111111111111111111111111111111114", "main", nil)
		require.EqualValues(t, 1, getGate(t, slug, "").BlockingCount)
	})

	t.Run("main seeing it brings it into the verdict", func(t *testing.T) {
		send(branchFixture, "1111111111111111111111111111111111111115", "main", nil)
		require.EqualValues(t, 2, getGate(t, slug, "").BlockingCount)
		require.Empty(t, findingNamed(newRuleTitle).OnlyOnBranches)
	})
}

// TestE2E_ProjectVerdictWithSetDefaultBranch pins the rule once a project names
// its default branch: a push build of any other branch stays out of the
// verdict even though it never named a base.
func TestE2E_ProjectVerdictWithSetDefaultBranch(t *testing.T) {
	slug := newProject(t, "verdict-set")
	key := mintKey(t, slug)
	request[projectDefaultBranch](t, http.MethodPut, "/api/v1/projects/"+slug, adminToken,
		map[string]any{"default_branch": "trunk"}, http.StatusOK)

	request[ingestResponse](t, http.MethodPost, "/api/v1/reports", key,
		ingestBodyWith(t, slug, "high-new.sarif.json", map[string]any{
			"commit_sha": "3333333333333333333333333333333333333333", "branch": "push-only",
		}), http.StatusCreated)
	require.EqualValues(t, 0, getGate(t, slug, "").BlockingCount)
	require.EqualValues(t, 2, getGate(t, slug, "branch=push-only").BlockingCount)

	request[ingestResponse](t, http.MethodPost, "/api/v1/reports", key,
		ingestBodyWith(t, slug, "high-medium.sarif.json", map[string]any{
			"commit_sha": "3333333333333333333333333333333333333334", "branch": "trunk",
		}), http.StatusCreated)
	require.EqualValues(t, 1, getGate(t, slug, "").BlockingCount, "the default branch's own high")
}

// TestE2E_ProjectVerdictFailsClosedWithoutBranch pins that a report naming no
// branch counts. Nothing shows it is off the default branch.
func TestE2E_ProjectVerdictFailsClosedWithoutBranch(t *testing.T) {
	slug := newProject(t, "verdict-no-branch")
	key := mintKey(t, slug)
	request[projectDefaultBranch](t, http.MethodPut, "/api/v1/projects/"+slug, adminToken,
		map[string]any{"default_branch": "main"}, http.StatusOK)
	request[ingestResponse](t, http.MethodPost, "/api/v1/reports", key,
		ingestBodyWith(t, slug, "high-new.sarif.json", map[string]any{
			"commit_sha": "4444444444444444444444444444444444444444",
		}), http.StatusCreated)
	require.EqualValues(t, 2, getGate(t, slug, "").BlockingCount)
}
