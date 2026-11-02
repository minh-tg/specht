package usecase

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/domain"
	"github.com/minh-tg/specht/internal/port"
)

const ownEarlierCommit = "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678"

// baselineOn configures the carry harness so the base revision resolves to a
// completed full report on reportBranch (nil for a report without a branch),
// through the commit lookup when byCommit is set and the branch lookup
// otherwise. changeBranches lists the branches BranchHasChangeReport answers
// true for. The baseline observed f-carried and f-old.
func baselineOn(reportBranch *string, byCommit bool, changeBranches ...string) func(rr *mockReportRepo, fr *mockFindingRepo) {
	return func(rr *mockReportRepo, fr *mockFindingRepo) {
		resolve := func(ctx context.Context, projectID, scanner, revision string) (port.CompletedReport, error) {
			return port.CompletedReport{ID: carryBaselineID, ToolName: scanner, Branch: reportBranch, ScanMode: "full", Completeness: "complete"}, nil
		}
		if byCommit {
			rr.byCommitFn = resolve
		} else {
			rr.byBranchFn = resolve
		}
		record := rr.branchHasChangeFn
		rr.branchHasChangeFn = func(ctx context.Context, projectID, branch string) (bool, error) {
			_, _ = record(ctx, projectID, branch)
			for _, b := range changeBranches {
				if b == branch {
					return true, nil
				}
			}
			return false, nil
		}
		fr.listFindingIDsPresentInReportFn = func(ctx context.Context, reportID string, ids []string) ([]string, error) {
			return []string{"f-carried", "f-old"}, nil
		}
	}
}

func strRef(s string) *string { return &s }

// requireBaselineUsed asserts the classification against a trusted baseline:
// the baseline saw f-carried and f-old, so only f-new and f-carried-reg are
// introduced, and the carry lookups never run.
func requireBaselineUsed(t *testing.T, out *IngestReportOutput, calls *carryCalls) {
	t.Helper()
	assert.Equal(t, 2, out.IntroducedCount)
	assert.Equal(t, 2, out.PreExistingCount)
	assert.Equal(t, map[string]string{"f-new": "new", "f-carried-reg": "new"}, entryTypes(calls.entries))
	require.NotNil(t, calls.baseRecorded)
	assert.Equal(t, carryBaselineID, *calls.baseRecorded)
	assert.Zero(t, calls.previousLookups)
}

func TestIngest_BaselineOfTheBranchItselfIsRefused(t *testing.T) {
	uc, calls := carryHarness(t, baselineOn(strRef("feat/x"), false, "feat/x"))
	out, err := carryIngest(t, uc, "feat/x", "feat/x")
	require.NoError(t, err)
	requireCarried(t, out, calls)
	assert.Equal(t, []string{"feat/x"}, calls.branchChecked,
		"only the carry rule asks about the branch; a report of the branch itself is refused before any trunk check")
}

func TestIngest_BaselineAtAnEarlierCommitOfTheBranchIsRefused(t *testing.T) {
	uc, calls := carryHarness(t, baselineOn(strRef("feat/x"), true))
	out, err := carryIngest(t, uc, "feat/x", ownEarlierCommit)
	require.NoError(t, err)
	requireCarried(t, out, calls)
	assert.Empty(t, calls.branchChecked, "a report of the branch itself is refused before any trunk check")
}

func TestIngest_BaselineOnAnotherChangeBranchIsRefused(t *testing.T) {
	uc, calls := carryHarness(t, baselineOn(strRef("feat/other"), false, "feat/other"))
	out, err := carryIngest(t, uc, "feat/x", "feat/other")
	require.NoError(t, err)
	requireCarried(t, out, calls)
	assert.Contains(t, calls.branchChecked, "feat/other")
}

func TestIngest_CommitBaselineOnAChangeBranchIsRefused(t *testing.T) {
	uc, calls := carryHarness(t, baselineOn(strRef("feat/other"), true, "feat/other"))
	out, err := carryIngest(t, uc, "feat/x", ownEarlierCommit)
	require.NoError(t, err)
	requireCarried(t, out, calls)
	assert.Contains(t, calls.branchChecked, "feat/other")
}

func TestIngest_TrunkBaselineIsUsed(t *testing.T) {
	t.Run("by branch name", func(t *testing.T) {
		uc, calls := carryHarness(t, baselineOn(strRef("main"), false))
		out, err := carryIngest(t, uc, "feat/x", "main")
		require.NoError(t, err)
		requireBaselineUsed(t, out, calls)
		assert.Equal(t, []string{"main"}, calls.branchChecked)
	})
	t.Run("by commit", func(t *testing.T) {
		uc, calls := carryHarness(t, baselineOn(strRef("main"), true))
		out, err := carryIngest(t, uc, "feat/x", ownEarlierCommit)
		require.NoError(t, err)
		requireBaselineUsed(t, out, calls)
		assert.Equal(t, []string{"main"}, calls.branchChecked)
	})
	t.Run("a report without a branch", func(t *testing.T) {
		uc, calls := carryHarness(t, baselineOn(nil, true))
		out, err := carryIngest(t, uc, "feat/x", ownEarlierCommit)
		require.NoError(t, err)
		requireBaselineUsed(t, out, calls)
		assert.Empty(t, calls.branchChecked)
	})
}

// The server stores no default branch. A main that was once the head of a
// pull request is a change branch like any other, so its reports stop being
// baselines and a pull request against it falls back to the carry rule: debt
// known to the project stays pre-existing and what the branch introduced
// earlier stays introduced, so the fallback never blocks on main's debt.
func TestIngest_DefaultBranchOnceAPullRequestHeadFallsBackToCarry(t *testing.T) {
	uc, calls := carryHarness(t, baselineOn(strRef("main"), false, "main"))
	out, err := carryIngest(t, uc, "feat/x", "main")
	require.NoError(t, err)
	requireCarried(t, out, calls)
	assert.Contains(t, calls.branchChecked, "main")
}

func TestIngest_BaselineBranchCheckErrorFailsTheIngest(t *testing.T) {
	boom := errors.New("boom")
	uc, _ := carryHarness(t, func(rr *mockReportRepo, fr *mockFindingRepo) {
		baselineOn(strRef("main"), false)(rr, fr)
		rr.branchHasChangeFn = func(ctx context.Context, projectID, branch string) (bool, error) {
			return false, boom
		}
	})
	_, err := carryIngest(t, uc, "feat/x", "main")
	require.ErrorIs(t, err, boom)
}

func TestResolveScanMode_RefusedBaselineFallsBackToFull(t *testing.T) {
	pr, rr, fr := makeTestRepos()
	rr.byBranchFn = func(ctx context.Context, projectID, scanner, branch string) (port.CompletedReport, error) {
		return port.CompletedReport{ID: "own", ToolName: scanner, Branch: strRef("feat/x"), ScanMode: "full"}, nil
	}
	uc := New(Deps{Stores: &port.Stores{Projects: pr, Reports: rr, Findings: fr}})

	mode, reason, baseline, err := uc.resolveScanMode(context.Background(), makeProject(true),
		&incrementalStub{mockScanner{name: "semgrep"}},
		IngestReportInput{Scanner: "semgrep", ScanMode: ScanModeIncremental, Branch: "feat/x", BaseRevision: "feat/x"}, &domain.NormalizedReport{})
	require.NoError(t, err)
	assert.Equal(t, ScanModeFull, mode)
	assert.Contains(t, reason, `no completed full baseline for base_revision "feat/x"`)
	assert.Contains(t, reason, `branch "feat/x" itself`)
	assert.Empty(t, baseline)
}

// A trunk baseline declared filtered cannot speak for f-carried and
// f-carried-reg: they fall back to the rules without a baseline, so the carry
// from the previous report decides, while f-old, which the baseline observed,
// stays pre-existing.
func TestIngest_FindingsAFilteredBaselineCannotSpeakForFallBackToCarry(t *testing.T) {
	uc, calls := carryHarness(t, func(rr *mockReportRepo, fr *mockFindingRepo) {
		baselineOn(strRef("main"), false)(rr, fr)
		fr.baselineEvidenceFn = func(ctx context.Context, baselineID string, ids []string) (map[string]bool, error) {
			assert.Equal(t, carryBaselineID, baselineID)
			return map[string]bool{"f-old": true}, nil
		}
		fr.listReportIntroducedChangeTypesFn = func(ctx context.Context, reportID string, ids []string) (map[string]string, error) {
			assert.ElementsMatch(t, []string{"f-carried", "f-carried-reg"}, ids,
				"only findings the baseline cannot speak for are looked up for a carry")
			return map[string]string{"f-carried": "new", "f-carried-reg": "regression"}, nil
		}
	})
	out, err := carryIngest(t, uc, "feat/x", "main")
	require.NoError(t, err)
	assert.Equal(t, 3, out.IntroducedCount)
	assert.Equal(t, 1, out.PreExistingCount)
	assert.Equal(t, map[string]string{"f-new": "new", "f-carried": "new", "f-carried-reg": "regression"}, entryTypes(calls.entries))
	require.NotNil(t, calls.baseRecorded)
	assert.Equal(t, carryBaselineID, *calls.baseRecorded)
	assert.Equal(t, 1, calls.previousLookups)
}

// A known finding the filtered baseline cannot speak for is pre-existing when
// the trunk still has it, the debt the filter hid. One the baseline speaks for
// and did not observe is introduced.
func TestIngest_FilteredBaselineNeverBlamesWhatItCouldNotSee(t *testing.T) {
	uc, calls := carryHarness(t, func(rr *mockReportRepo, fr *mockFindingRepo) {
		baselineOn(strRef("main"), false)(rr, fr)
		fr.baselineEvidenceFn = func(ctx context.Context, baselineID string, ids []string) (map[string]bool, error) {
			return map[string]bool{"f-old": true, "f-carried-reg": false}, nil
		}
		fr.onTrunkFn = func(ctx context.Context, projectID string, defaultBranch *string, ids []string) (map[string]bool, error) {
			assert.Equal(t, []string{"f-carried"}, ids, "only the finding without evidence is asked about")
			return map[string]bool{"f-carried": true}, nil
		}
		fr.listReportIntroducedChangeTypesFn = func(ctx context.Context, reportID string, ids []string) (map[string]string, error) {
			return nil, nil
		}
	})
	out, err := carryIngest(t, uc, "feat/x", "main")
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"f-new": "new", "f-carried-reg": "new"}, entryTypes(calls.entries),
		"f-carried has no evidence and the trunk has it, so it is pre-existing")
	assert.Equal(t, 2, out.PreExistingCount)
}

func projectWithDefaultBranch(branch string) port.Project {
	p := makeProject(true)
	p.DefaultBranch = &branch
	return p
}

// A default branch set on the project is a trunk even after it was the head
// of a pull request: its reports are baselines again.
func TestIngest_DefaultBranchSetOnTheProjectIsATrunk(t *testing.T) {
	t.Run("by branch name", func(t *testing.T) {
		uc, calls := carryHarnessFor(t, projectWithDefaultBranch("main"), baselineOn(strRef("main"), false, "main"))
		out, err := carryIngest(t, uc, "feat/x", "main")
		require.NoError(t, err)
		requireBaselineUsed(t, out, calls)
		assert.Empty(t, calls.branchChecked, "the setting decides without asking the branch history")
	})
	t.Run("by commit", func(t *testing.T) {
		uc, calls := carryHarnessFor(t, projectWithDefaultBranch("main"), baselineOn(strRef("main"), true, "main"))
		out, err := carryIngest(t, uc, "feat/x", ownEarlierCommit)
		require.NoError(t, err)
		requireBaselineUsed(t, out, calls)
	})
}

// The setting names the one trunk. Every other branch is refused, with or
// without change reports, and so is a report without a branch and a report of
// the uploading branch itself, even when that is the default branch. Each of
// them could have been uploaded by the ingest key just to serve as the base.
func TestIngest_DefaultBranchSettingTrustsOnlyThatBranch(t *testing.T) {
	t.Run("develop is a change branch", func(t *testing.T) {
		uc, calls := carryHarnessFor(t, projectWithDefaultBranch("main"), baselineOn(strRef("develop"), false, "develop"))
		out, err := carryIngest(t, uc, "feat/x", "develop")
		require.NoError(t, err)
		requireCarried(t, out, calls)
	})
	t.Run("a release branch without change reports", func(t *testing.T) {
		uc, calls := carryHarnessFor(t, projectWithDefaultBranch("main"), baselineOn(strRef("release/1"), false))
		out, err := carryIngest(t, uc, "feat/x", "release/1")
		require.NoError(t, err)
		requireCarried(t, out, calls)
		assert.Empty(t, calls.branchChecked, "the setting decides without asking the branch history")
	})
	t.Run("a fresh branch name", func(t *testing.T) {
		uc, calls := carryHarnessFor(t, projectWithDefaultBranch("main"), baselineOn(strRef("attacker-trunk"), false))
		out, err := carryIngest(t, uc, "feat/x", "attacker-trunk")
		require.NoError(t, err)
		requireCarried(t, out, calls)
	})
	t.Run("a report without a branch", func(t *testing.T) {
		uc, calls := carryHarnessFor(t, projectWithDefaultBranch("main"), baselineOn(nil, true))
		out, err := carryIngest(t, uc, "feat/x", ownEarlierCommit)
		require.NoError(t, err)
		requireCarried(t, out, calls)
	})
	t.Run("the default branch naming itself", func(t *testing.T) {
		uc, calls := carryHarnessFor(t, projectWithDefaultBranch("main"), baselineOn(strRef("main"), false))
		out, err := carryIngest(t, uc, "main", "main")
		require.NoError(t, err)
		requireNotCarried(t, out, calls)
		assert.Nil(t, calls.baseRecorded, "a report of the branch itself is no baseline")
	})
}

// A push build of the default branch is a trunk build even after the branch
// was a pull request head, so it never carries introductions forward.
func TestIngest_DefaultBranchPushBuildDoesNotCarry(t *testing.T) {
	uc, calls := carryHarnessFor(t, projectWithDefaultBranch("main"), func(rr *mockReportRepo, fr *mockFindingRepo) {
		rr.branchHasChangeFn = func(ctx context.Context, projectID, branch string) (bool, error) {
			return true, nil
		}
	})
	out, err := carryIngest(t, uc, "main", "")
	require.NoError(t, err)
	requireNotCarried(t, out, calls)

	uc, calls = carryHarnessFor(t, projectWithDefaultBranch("main"), nil)
	out, err = carryIngest(t, uc, "main", "release/1")
	require.NoError(t, err)
	requireCarried(t, out, calls)
}

// A trunk that scans several images has one newest report per image. The
// baseline is the newest one in the uploading report's scan scope moved to the
// trunk branch, by branch name and by commit, and only without one the newest
// report of any scope.
func TestIngest_BaselinePrefersTheUploadingReportsScope(t *testing.T) {
	nr := &domain.NormalizedReport{Target: &domain.TargetInfo{Kind: "container", Identifier: "myapp:latest"}}
	want := scanScopeHash(IngestReportInput{Scanner: "trivy", Branch: "main"}, nr)
	const scopedID = "00000000-0000-0000-0000-0000000000b9"
	scoped := func(gotScope *string) func(context.Context, string, string, string, string) (port.CompletedReport, error) {
		return func(ctx context.Context, projectID, scanner, revision, scope string) (port.CompletedReport, error) {
			*gotScope = scope
			return port.CompletedReport{ID: scopedID, ToolName: scanner, Branch: strRef("main"), ScanMode: "full", Completeness: "complete"}, nil
		}
	}
	t.Run("by branch name", func(t *testing.T) {
		var gotScope string
		uc, calls := carryHarness(t, func(rr *mockReportRepo, fr *mockFindingRepo) {
			baselineOn(strRef("main"), false)(rr, fr)
			rr.byBranchInScopeFn = scoped(&gotScope)
		})
		_, err := carryIngest(t, uc, "feat/x", "main")
		require.NoError(t, err)
		assert.Equal(t, want, gotScope)
		require.NotNil(t, calls.baseRecorded)
		assert.Equal(t, scopedID, *calls.baseRecorded)
	})
	t.Run("by commit", func(t *testing.T) {
		var gotScope string
		uc, calls := carryHarness(t, func(rr *mockReportRepo, fr *mockFindingRepo) {
			baselineOn(strRef("main"), true)(rr, fr)
			rr.byCommitInScopeFn = scoped(&gotScope)
		})
		_, err := carryIngest(t, uc, "feat/x", ownEarlierCommit)
		require.NoError(t, err)
		assert.Equal(t, want, gotScope)
		require.NotNil(t, calls.baseRecorded)
		assert.Equal(t, scopedID, *calls.baseRecorded)
	})
	t.Run("no report in that scope", func(t *testing.T) {
		uc, calls := carryHarness(t, baselineOn(strRef("main"), false))
		_, err := carryIngest(t, uc, "feat/x", "main")
		require.NoError(t, err)
		require.NotNil(t, calls.baseRecorded)
		assert.Equal(t, carryBaselineID, *calls.baseRecorded, "the newest main report of any scope")
	})
}
