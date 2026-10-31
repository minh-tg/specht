//go:build e2e

package e2e

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// carryPush posts one fixture as a build of branch at commit, with an
// optional base revision, and gates on introduced findings only.
func carryPush(t *testing.T, slug, key, fixture, branch, commit, base string) ingestResponse {
	t.Helper()
	extra := map[string]any{
		"branch":               branch,
		"commit_sha":           commit,
		"gate_introduced_only": true,
	}
	if base != "" {
		extra["base_revision"] = base
	}
	return request[ingestResponse](t, http.MethodPost, "/api/v1/reports", key,
		ingestBodyWith(t, slug, fixture, extra), http.StatusCreated)
}

// TestE2E_IntroducedCarriesOnBranchWithUnscannedBase pins the fix for a branch
// that shed its own blocker by pushing again: the PR targets a branch this
// scanner never scanned, so no baseline resolves and every finding is new on
// push 1. Push 2 sees the same findings as known; they must stay introduced
// until the branch fixes them, also on a push build that sends no base ref.
func TestE2E_IntroducedCarriesOnBranchWithUnscannedBase(t *testing.T) {
	slug := newProject(t, "carry-unscanned")
	key := mintKey(t, slug)

	push1 := carryPush(t, slug, key, "high-new.sarif.json", "feat/x",
		"a100000000000000000000000000000000000001", "main")
	require.True(t, push1.ThresholdBreached, "both highs are new to the project and block")
	require.Equal(t, 2, push1.IntroducedCount)

	push2 := carryPush(t, slug, key, "high-new.sarif.json", "feat/x",
		"a100000000000000000000000000000000000002", "main")
	require.True(t, push2.ThresholdBreached,
		"pushing again without fixing anything must not pass the change gate")
	require.Equal(t, 2, push2.IntroducedCount, "both highs carry from push 1")
	require.Equal(t, 0, push2.PreExistingCount)
	gs := getGate(t, slug, "introduced_only=1&report_id="+push2.ReportID)
	require.True(t, gs.ThresholdBreached)
	require.EqualValues(t, 2, gs.BlockingCount)

	push3 := carryPush(t, slug, key, "high-new.sarif.json", "feat/x",
		"a100000000000000000000000000000000000003", "")
	require.True(t, push3.ThresholdBreached,
		"a push build without a base ref on the same branch still blocks")
	require.Equal(t, 2, push3.IntroducedCount)

	fixed := carryPush(t, slug, key, "medium.sarif.json", "feat/x",
		"a100000000000000000000000000000000000004", "main")
	require.False(t, fixed.ThresholdBreached, "the branch fixed both highs")
	require.Equal(t, 1, fixed.IntroducedCount, "only the new medium, which does not block")
	gs = getGate(t, slug, "introduced_only=1&report_id="+fixed.ReportID)
	require.False(t, gs.ThresholdBreached)
	require.Zero(t, gs.BlockingCount)
}

// TestE2E_IntroducedCarryKeepsBaselineOrigin pins that a carry only keeps
// what the branch introduced against its real baseline: debt the target
// branch already had stays pre-existing on later push builds, and a PR build
// with a resolvable baseline classifies exactly as before.
func TestE2E_IntroducedCarryKeepsBaselineOrigin(t *testing.T) {
	slug := newProject(t, "carry-origin")
	key := mintKey(t, slug)

	carryPush(t, slug, key, "high.sarif.json", "main", baseSHA, "")

	pr := carryPush(t, slug, key, "high-new.sarif.json", "feat/y",
		"b100000000000000000000000000000000000001", "main")
	require.True(t, pr.ThresholdBreached)
	require.Equal(t, 1, pr.IntroducedCount, "only the new rule is introduced against main")
	require.Equal(t, 1, pr.PreExistingCount, "main's high is pre-existing")

	push := carryPush(t, slug, key, "high-new.sarif.json", "feat/y",
		"b100000000000000000000000000000000000002", "")
	require.True(t, push.ThresholdBreached, "the introduced high still blocks on a push build")
	require.Equal(t, 1, push.IntroducedCount, "main's debt is not carried")
	require.Equal(t, 1, push.PreExistingCount)
	gs := getGate(t, slug, "introduced_only=1&report_id="+push.ReportID)
	require.EqualValues(t, 1, gs.BlockingCount)

	again := carryPush(t, slug, key, "high-new.sarif.json", "feat/y",
		"b100000000000000000000000000000000000003", "main")
	require.True(t, again.ThresholdBreached, "a resolvable baseline still sees the new rule as introduced")
	require.Equal(t, 1, again.IntroducedCount)
	require.Equal(t, 1, again.PreExistingCount)

	fixed := carryPush(t, slug, key, "high.sarif.json", "feat/y",
		"b100000000000000000000000000000000000004", "")
	require.False(t, fixed.ThresholdBreached, "only main's debt is left")
	require.Equal(t, 0, fixed.IntroducedCount)
}

// TestE2E_TrunkPushBuildsDoNotCarry pins the trunk rule: push builds on a
// branch that no report ever compared against another base count only
// findings new to the project, once. The first-scan backlog of main does not
// stay introduced, also after PR builds have named main as their base.
func TestE2E_TrunkPushBuildsDoNotCarry(t *testing.T) {
	slug := newProject(t, "carry-trunk")
	key := mintKey(t, slug)

	first := carryPush(t, slug, key, "high-medium.sarif.json", "main",
		"c100000000000000000000000000000000000001", "")
	require.True(t, first.ThresholdBreached, "the first scan of the project sees everything as new")
	require.Equal(t, 2, first.IntroducedCount)

	second := carryPush(t, slug, key, "high-medium.sarif.json", "main",
		"c100000000000000000000000000000000000002", "")
	require.False(t, second.ThresholdBreached, "main's own backlog is not carried")
	require.Equal(t, 0, second.IntroducedCount)
	require.Equal(t, 2, second.PreExistingCount)

	pr := carryPush(t, slug, key, "high-new.sarif.json", "feat/z",
		"c100000000000000000000000000000000000003", "main")
	require.True(t, pr.ThresholdBreached)
	require.Equal(t, 1, pr.IntroducedCount)

	merged := carryPush(t, slug, key, "high-new.sarif.json", "main",
		"c100000000000000000000000000000000000004", "")
	require.False(t, merged.ThresholdBreached,
		"a finding first seen on the PR branch is known by the time main scans it")
	require.Equal(t, 0, merged.IntroducedCount)

	later := carryPush(t, slug, key, "high-new.sarif.json", "main",
		"c100000000000000000000000000000000000005", "")
	require.False(t, later.ThresholdBreached)
	require.Equal(t, 0, later.IntroducedCount)
}
