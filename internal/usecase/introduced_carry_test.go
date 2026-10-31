package usecase

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/domain"
	"github.com/minh-tg/specht/internal/port"
	"github.com/minh-tg/specht/internal/scanner"
)

func TestClassifyIngestChange(t *testing.T) {
	cases := []struct {
		name         string
		exists       bool
		regression   bool
		baselineID   string
		baselineSeen bool
		carried      string
		wantIntro    bool
		wantType     string
	}{
		{name: "regression wins over everything", exists: true, regression: true, baselineID: "b", baselineSeen: true, wantIntro: true, wantType: "regression"},
		{name: "baseline: new to project", baselineID: "b", wantIntro: true, wantType: "new"},
		{name: "baseline: known but absent from baseline", exists: true, baselineID: "b", wantIntro: true, wantType: "new"},
		{name: "baseline: seen by baseline", exists: true, baselineID: "b", baselineSeen: true},
		{name: "baseline: seen by baseline ignores carry", exists: true, baselineID: "b", baselineSeen: true, carried: "new"},
		{name: "baseline: absent from baseline keeps new over carried regression", exists: true, baselineID: "b", carried: "regression", wantIntro: true, wantType: "new"},
		{name: "no baseline: new to project", wantIntro: true, wantType: "new"},
		{name: "no baseline: known, nothing carried", exists: true},
		{name: "no baseline: known, carried new", exists: true, carried: "new", wantIntro: true, wantType: "new"},
		{name: "no baseline: known, carried regression", exists: true, carried: "regression", wantIntro: true, wantType: "regression"},
		{name: "no baseline: unknown ignores carry", carried: "regression", wantIntro: true, wantType: "new"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			intro, ct := classifyIngestChange(tc.exists, tc.regression, tc.baselineID, tc.baselineSeen, tc.carried)
			assert.Equal(t, tc.wantIntro, intro)
			assert.Equal(t, tc.wantType, ct)
		})
	}
}

const (
	carryReportID   = "00000000-0000-0000-0000-0000000000c0"
	carryPreviousID = "00000000-0000-0000-0000-0000000000c1"
	carryBaselineID = "00000000-0000-0000-0000-0000000000b0"
)

// carryHarness ingests four findings: fp-new is unknown, fp-carried and
// fp-carried-reg were introduced by the previous report in scope (as new and
// as a regression), and fp-old is known debt the previous report did not
// introduce. The returned calls record which carry lookups ran.
type carryCalls struct {
	branchChecked   []string
	previousLookups int
	introducedOf    []string
	entries         []port.IntroducedFindingEntry
	baseRecorded    *string
}

func carryHarness(t *testing.T, configure func(rr *mockReportRepo, fr *mockFindingRepo)) (*Usecases, *carryCalls) {
	t.Helper()
	calls := &carryCalls{}
	pr, rr, fr := makeTestRepos()
	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return makeProject(true), nil
	}
	report := makeReport()
	report.ID = carryReportID
	rr.createFn = func(ctx context.Context, arg port.CreateReportInput) (port.Report, error) {
		return report, nil
	}
	rr.updateStatusFn = func(ctx context.Context, id, projectID, status string, totalFindings int32, errorMsg *string) (port.Report, error) {
		return report, nil
	}
	rr.branchHasChangeFn = func(ctx context.Context, projectID, branch string) (bool, error) {
		calls.branchChecked = append(calls.branchChecked, branch)
		return false, nil
	}
	rr.previousInScopeFn = func(ctx context.Context, projectID, reportID string) (string, error) {
		calls.previousLookups++
		assert.Equal(t, carryReportID, reportID, "the previous report is looked up relative to the new report")
		return carryPreviousID, nil
	}
	known := []port.Finding{
		{ID: "f-carried", ProjectID: makeProject(true).ID, FindingKind: "sca", Fingerprint: "fp-carried", State: "open", AnalysisState: "unanalyzed"},
		{ID: "f-carried-reg", ProjectID: makeProject(true).ID, FindingKind: "sca", Fingerprint: "fp-carried-reg", State: "open", AnalysisState: "unanalyzed"},
		{ID: "f-old", ProjectID: makeProject(true).ID, FindingKind: "sca", Fingerprint: "fp-old", State: "open", AnalysisState: "unanalyzed"},
	}
	fr.listFindingsByFingerprintsFn = func(ctx context.Context, projectID, kind string, fps []string) ([]port.Finding, error) {
		return known, nil
	}
	fr.listReportIntroducedChangeTypesFn = func(ctx context.Context, reportID string, ids []string) (map[string]string, error) {
		calls.introducedOf = append(calls.introducedOf, reportID)
		assert.ElementsMatch(t, []string{"f-carried", "f-carried-reg", "f-old"}, ids)
		return map[string]string{"f-carried": "new", "f-carried-reg": "regression"}, nil
	}
	fr.upsertFn = func(ctx context.Context, in port.UpsertFindingInput) (port.Finding, error) {
		for _, k := range known {
			if k.Fingerprint == in.Fingerprint {
				return k, nil
			}
		}
		return port.Finding{ID: "f-new", ProjectID: in.ProjectID, FindingKind: in.FindingKind, Fingerprint: in.Fingerprint, State: "open"}, nil
	}
	fr.createOccurrenceFn = func(ctx context.Context, arg port.OccurrenceInput) (port.Occurrence, error) {
		return port.Occurrence{}, nil
	}
	fr.upsertDimensionFn = func(ctx context.Context, arg port.DimensionInput) error { return nil }
	fr.recordReportIntroducedFindingsFn = func(ctx context.Context, reportID string, baseID *string, entries []port.IntroducedFindingEntry) error {
		calls.entries = entries
		calls.baseRecorded = baseID
		return nil
	}
	if configure != nil {
		configure(rr, fr)
	}

	reg := scanner.NewRegistry()
	require.NoError(t, reg.Register(&mockScanner{
		name: "trivy",
		parseFn: func(ctx context.Context, input []byte) (*domain.NormalizedReport, error) {
			return &domain.NormalizedReport{
				ContractVersion: 1, FingerprintVersion: 1,
				Completeness: domain.CompletenessComplete, ScanType: domain.ScanTypeImage,
				CoveredFindingKinds: []string{"sca", "sast", "iac", "secret", "dast"},
				Target:              &domain.TargetInfo{Kind: "container", Identifier: "myapp:latest"},
				Findings: []domain.NormalizedFinding{
					{Fingerprint: "fp-new", FindingKind: "sca", Title: "New", Severity: domain.SeverityHigh, Score: 7.5},
					{Fingerprint: "fp-carried", FindingKind: "sca", Title: "Carried", Severity: domain.SeverityHigh, Score: 7.5},
					{Fingerprint: "fp-carried-reg", FindingKind: "sca", Title: "Carried regression", Severity: domain.SeverityHigh, Score: 7.5},
					{Fingerprint: "fp-old", FindingKind: "sca", Title: "Old", Severity: domain.SeverityHigh, Score: 7.5},
				},
			}, nil
		},
	}))
	uc := New(Deps{
		Stores: &port.Stores{
			Projects: pr, Reports: rr, Findings: fr,
			Targets: stubTargetRepo(), Artifacts: stubArtifactRepo(),
			Waivers: &mockWaiverRepo{},
		},
		Registry: reg,
	})
	return uc, calls
}

func carryIngest(t *testing.T, uc *Usecases, branch, base string) (*IngestReportOutput, error) {
	t.Helper()
	return uc.IngestReport(context.Background(), IngestReportInput{
		ProjectSlug:  "my-app",
		Scanner:      "trivy",
		RawData:      json.RawMessage(`{"test": true}`),
		Branch:       branch,
		CommitSha:    "abcdef1234567",
		BaseRevision: base,
	})
}

func entryTypes(entries []port.IntroducedFindingEntry) map[string]string {
	out := make(map[string]string, len(entries))
	for _, e := range entries {
		out[e.FindingID] = e.ChangeType
	}
	return out
}

func requireCarried(t *testing.T, out *IngestReportOutput, calls *carryCalls) {
	t.Helper()
	assert.Equal(t, 4, out.TotalFindings)
	assert.Equal(t, 3, out.IntroducedCount, "the new finding plus both carried findings are introduced")
	assert.Equal(t, 1, out.PreExistingCount, "debt the previous report did not introduce stays pre-existing")
	assert.Equal(t, map[string]string{"f-new": "new", "f-carried": "new", "f-carried-reg": "regression"}, entryTypes(calls.entries),
		"a carried finding keeps the change type the previous report recorded")
	assert.Nil(t, calls.baseRecorded, "no baseline resolved, so none is recorded")
	assert.Equal(t, 1, calls.previousLookups)
	assert.Equal(t, []string{carryPreviousID}, calls.introducedOf)
}

func requireNotCarried(t *testing.T, out *IngestReportOutput, calls *carryCalls) {
	t.Helper()
	assert.Equal(t, 4, out.TotalFindings)
	assert.Equal(t, 1, out.IntroducedCount, "only the finding new to the project is introduced")
	assert.Equal(t, 3, out.PreExistingCount)
	assert.Equal(t, map[string]string{"f-new": "new"}, entryTypes(calls.entries))
	assert.Zero(t, calls.previousLookups, "no carry means no previous-report lookup")
	assert.Empty(t, calls.introducedOf)
}

func TestIngest_CarryUnresolvedBaseRevisionOnChangeBranch(t *testing.T) {
	uc, calls := carryHarness(t, nil)
	out, err := carryIngest(t, uc, "feat/x", "main")
	require.NoError(t, err)
	requireCarried(t, out, calls)
	assert.Empty(t, calls.branchChecked, "a base revision on the report itself marks a change branch")
}

func TestIngest_CarryPushBuildOnBranchWithChangeReport(t *testing.T) {
	uc, calls := carryHarness(t, func(rr *mockReportRepo, fr *mockFindingRepo) {
		rr.branchHasChangeFn = func(ctx context.Context, projectID, branch string) (bool, error) {
			assert.Equal(t, "feat/x", branch)
			return true, nil
		}
	})
	out, err := carryIngest(t, uc, "feat/x", "")
	require.NoError(t, err)
	requireCarried(t, out, calls)
}

func TestIngest_NoCarryOnTrunkPushBuild(t *testing.T) {
	uc, calls := carryHarness(t, nil)
	out, err := carryIngest(t, uc, "main", "")
	require.NoError(t, err)
	requireNotCarried(t, out, calls)
	assert.Equal(t, []string{"main"}, calls.branchChecked)
}

func TestIngest_NoCarryWhenBaseRevisionNamesTheBranch(t *testing.T) {
	uc, calls := carryHarness(t, nil)
	out, err := carryIngest(t, uc, "main", "main")
	require.NoError(t, err)
	requireNotCarried(t, out, calls)
	assert.Equal(t, []string{"main"}, calls.branchChecked,
		"a base equal to the branch is not a change, so the branch history decides")
}

func TestIngest_NoCarryWithoutBranch(t *testing.T) {
	uc, calls := carryHarness(t, nil)
	out, err := carryIngest(t, uc, "", "main")
	require.NoError(t, err)
	requireNotCarried(t, out, calls)
	assert.Empty(t, calls.branchChecked)
}

func TestIngest_NoCarryWithoutPreviousReportInScope(t *testing.T) {
	uc, calls := carryHarness(t, func(rr *mockReportRepo, fr *mockFindingRepo) {
		rr.previousInScopeFn = func(ctx context.Context, projectID, reportID string) (string, error) {
			return "", port.ErrNotFound
		}
	})
	out, err := carryIngest(t, uc, "feat/x", "main")
	require.NoError(t, err)
	assert.Equal(t, 1, out.IntroducedCount)
	assert.Equal(t, map[string]string{"f-new": "new"}, entryTypes(calls.entries))
	assert.Empty(t, calls.introducedOf)
}

// A resolvable baseline keeps today's classification exactly: the carry
// lookups never run, and a finding the baseline saw is pre-existing even when
// an earlier report on the branch introduced it.
func TestIngest_ResolvedBaselineNeverCarries(t *testing.T) {
	uc, calls := carryHarness(t, func(rr *mockReportRepo, fr *mockFindingRepo) {
		rr.byCommitFn = func(ctx context.Context, projectID, scanner, commit string) (port.CompletedReport, error) {
			return port.CompletedReport{ID: carryBaselineID, ToolName: scanner}, nil
		}
		fr.listFindingIDsPresentInReportFn = func(ctx context.Context, reportID string, ids []string) ([]string, error) {
			assert.Equal(t, carryBaselineID, reportID)
			return []string{"f-carried", "f-old"}, nil
		}
	})
	out, err := carryIngest(t, uc, "feat/x", "main")
	require.NoError(t, err)
	assert.Equal(t, 2, out.IntroducedCount, "fp-new and the baseline-absent fp-carried-reg")
	assert.Equal(t, 2, out.PreExistingCount)
	assert.Equal(t, map[string]string{"f-new": "new", "f-carried-reg": "new"}, entryTypes(calls.entries))
	require.NotNil(t, calls.baseRecorded)
	assert.Equal(t, carryBaselineID, *calls.baseRecorded)
	assert.Empty(t, calls.branchChecked)
	assert.Zero(t, calls.previousLookups)
	assert.Empty(t, calls.introducedOf)
}

func TestIngest_CarryLookupErrorsFailTheIngest(t *testing.T) {
	boom := errors.New("boom")
	t.Run("branch check", func(t *testing.T) {
		uc, _ := carryHarness(t, func(rr *mockReportRepo, fr *mockFindingRepo) {
			rr.branchHasChangeFn = func(ctx context.Context, projectID, branch string) (bool, error) {
				return false, boom
			}
		})
		_, err := carryIngest(t, uc, "feat/x", "")
		require.ErrorIs(t, err, boom)
	})
	t.Run("previous report", func(t *testing.T) {
		uc, _ := carryHarness(t, func(rr *mockReportRepo, fr *mockFindingRepo) {
			rr.previousInScopeFn = func(ctx context.Context, projectID, reportID string) (string, error) {
				return "", boom
			}
		})
		_, err := carryIngest(t, uc, "feat/x", "main")
		require.ErrorIs(t, err, boom)
	})
	t.Run("introduced rows", func(t *testing.T) {
		uc, _ := carryHarness(t, func(rr *mockReportRepo, fr *mockFindingRepo) {
			fr.listReportIntroducedChangeTypesFn = func(ctx context.Context, reportID string, ids []string) (map[string]string, error) {
				return nil, boom
			}
		})
		_, err := carryIngest(t, uc, "feat/x", "main")
		require.ErrorIs(t, err, boom)
	})
}
