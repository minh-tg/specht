package usecase

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/domain"
	"github.com/minh-tg/specht/internal/port"
	"github.com/minh-tg/specht/internal/scanner"
)

// revisionHarness builds an ingest stack with a single trivy finding and
// project/report/finding fakes wired for revision-attribution assertions.
// getByFingerprint controls whether the finding is new (port.ErrNotFound)
// or pre-existing.
func revisionHarness(t *testing.T, getByFingerprint func(context.Context, string, string, string) (port.Finding, error)) (*Usecases, *mockReportRepo, *mockFindingRepo, *port.CreateReportInput) {
	t.Helper()
	pr, rr, fr := makeTestRepos()
	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return makeProject(true), nil
	}
	var createdInput *port.CreateReportInput
	rr.createFn = func(ctx context.Context, arg port.CreateReportInput) (port.Report, error) {
		createdInput = &arg
		return makeReport(), nil
	}
	rr.updateStatusFn = func(ctx context.Context, id, projectID, status string, totalFindings int32, errorMsg *string) (port.Report, error) {
		return makeReport(), nil
	}
	fr.getByFingerprintFn = getByFingerprint
	fr.upsertFn = func(ctx context.Context, in port.UpsertFindingInput) (port.Finding, error) {
		return makeFinding(9), nil
	}
	fr.createOccurrenceFn = func(ctx context.Context, arg port.OccurrenceInput) (port.Occurrence, error) {
		return port.Occurrence{}, nil
	}
	fr.upsertDimensionFn = func(ctx context.Context, arg port.DimensionInput) error {
		return nil
	}
	fr.updateAnalysisFn = func(ctx context.Context, arg port.UpdateAnalysisInput) (port.Finding, error) {
		return makeFinding(9), nil
	}

	reg := scanner.NewRegistry()
	require.NoError(t, reg.Register(&mockScanner{
		name: "trivy",
		parseFn: func(ctx context.Context, input []byte) (*domain.NormalizedReport, error) {
			return &domain.NormalizedReport{
				ContractVersion:    1,
				FingerprintVersion: 1,
				Completeness:       domain.CompletenessComplete,
				ScanType:           domain.ScanTypeImage,
				Target:             &domain.TargetInfo{Kind: "container", Identifier: "myapp:latest"},
				Findings: []domain.NormalizedFinding{
					{
						Fingerprint: "fp-revision",
						FindingKind: "sca",
						Title:       "CVE-2024-1234",
						Severity:    domain.SeverityHigh,
						Score:       7.5,
					},
				},
			}, nil
		},
	}))

	uc := New(Deps{
		Stores: &port.Stores{
			Projects:  pr,
			Reports:   rr,
			Findings:  fr,
			Targets:   stubTargetRepo(),
			Artifacts: stubArtifactRepo(),
		},
		Registry: reg,
	})
	return uc, rr, fr, createdInput
}

func TestIngestReport_IncrementalRequiresBaseRevision(t *testing.T) {
	uc := New(Deps{})
	_, err := uc.IngestReport(context.Background(), IngestReportInput{
		ProjectSlug: "my-app",
		Scanner:     "trivy",
		RawData:     json.RawMessage(`{"test": true}`),
		ScanMode:    "incremental",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "base_revision")
}

func TestIngestReport_UnknownScanModeRejected(t *testing.T) {
	uc := New(Deps{})
	_, err := uc.IngestReport(context.Background(), IngestReportInput{
		ProjectSlug: "my-app",
		Scanner:     "trivy",
		RawData:     json.RawMessage(`{"test": true}`),
		ScanMode:    "delta",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "scan_mode")
}

func TestIngestReport_SetsIntroducedAttribution(t *testing.T) {
	uc, rr, fr, _ := revisionHarness(t, func(context.Context, string, string, string) (port.Finding, error) {
		return port.Finding{}, port.ErrNotFound
	})

	var gotFinding, gotReport string
	var gotCommit *string
	fr.setIntroducedByFn = func(ctx context.Context, findingID, reportID string, commitSha *string) (port.Finding, error) {
		gotFinding, gotReport, gotCommit = findingID, reportID, commitSha
		return makeFinding(9), nil
	}
	_ = rr

	result, err := uc.IngestReport(context.Background(), IngestReportInput{
		ProjectSlug: "my-app",
		Scanner:     "trivy",
		RawData:     json.RawMessage(`{"test": true}`),
		CommitSha:   "abc123",
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, makeFinding(9).ID, gotFinding)
	assert.Equal(t, makeReport().ID, gotReport)
	require.NotNil(t, gotCommit)
	assert.Equal(t, "abc123", *gotCommit)
}

func TestIngestReport_PreservesExistingAttribution(t *testing.T) {
	existing := makeFinding(9)
	reportID := "11111111-1111-1111-1111-111111111111"
	existing.IntroducedByReportID = &reportID
	uc, _, fr, _ := revisionHarness(t, func(context.Context, string, string, string) (port.Finding, error) {
		return existing, nil
	})

	calls := 0
	fr.setIntroducedByFn = func(ctx context.Context, findingID, reportID string, commitSha *string) (port.Finding, error) {
		calls++
		return makeFinding(9), nil
	}

	_, err := uc.IngestReport(context.Background(), IngestReportInput{
		ProjectSlug: "my-app",
		Scanner:     "trivy",
		RawData:     json.RawMessage(`{"test": true}`),
		CommitSha:   "def456",
	})
	require.NoError(t, err)
	assert.Zero(t, calls, "pre-existing attribution must never be silently rewritten")
}

func TestIngestReport_BackfillsMissingAttribution(t *testing.T) {
	existing := makeFinding(9)
	uc, _, fr, _ := revisionHarness(t, func(context.Context, string, string, string) (port.Finding, error) {
		return existing, nil
	})

	calls := 0
	fr.setIntroducedByFn = func(ctx context.Context, findingID, reportID string, commitSha *string) (port.Finding, error) {
		calls++
		return makeFinding(9), nil
	}

	_, err := uc.IngestReport(context.Background(), IngestReportInput{
		ProjectSlug: "my-app",
		Scanner:     "trivy",
		RawData:     json.RawMessage(`{"test": true}`),
		CommitSha:   "def456",
	})
	require.NoError(t, err)
	assert.Equal(t, 1, calls, "unattributed pre-existing findings gain attribution on observation")
}

func TestIngestReport_NormalizesRevisions(t *testing.T) {
	uc, rr, _, _ := revisionHarness(t, func(context.Context, string, string, string) (port.Finding, error) {
		return port.Finding{}, port.ErrNotFound
	})
	var created port.CreateReportInput
	rr.createFn = func(ctx context.Context, arg port.CreateReportInput) (port.Report, error) {
		created = arg
		return makeReport(), nil
	}

	_, err := uc.IngestReport(context.Background(), IngestReportInput{
		ProjectSlug: "my-app",
		Scanner:     "trivy",
		RawData:     json.RawMessage(`{"test": true}`),
		CommitSha:   "  ABC123  ",
	})
	require.NoError(t, err)
	require.NotNil(t, created.CommitSha)
	assert.Equal(t, "abc123", *created.CommitSha, "SHAs store canonical so comparisons never miss on case")
}

func TestIngestReport_IncrementalBaseEqualsCommitRejected(t *testing.T) {
	uc := New(Deps{})
	_, err := uc.IngestReport(context.Background(), IngestReportInput{
		ProjectSlug:  "my-app",
		Scanner:      "trivy",
		RawData:      json.RawMessage(`{"test": true}`),
		ScanMode:     "incremental",
		BaseRevision: "abc123",
		CommitSha:    "abc123",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "base_revision")
}

func TestToFinding_MapsIntroducedAttribution(t *testing.T) {
	reportID := "11111111-1111-1111-1111-111111111111"
	commit := "abc123"
	f := makeFinding(9)
	f.IntroducedByReportID = &reportID
	f.IntroducedCommitSha = &commit

	resp := toFinding(f)
	require.NotNil(t, resp.IntroducedByReportID)
	assert.Equal(t, reportID, *resp.IntroducedByReportID)
	require.NotNil(t, resp.IntroducedCommitSha)
	assert.Equal(t, commit, *resp.IntroducedCommitSha)
}

func TestToFinding_NilAttributionStaysNil(t *testing.T) {
	resp := toFinding(makeFinding(9))
	assert.Nil(t, resp.IntroducedByReportID)
	assert.Nil(t, resp.IntroducedCommitSha)
}

func TestToReport_MapsRevisionContext(t *testing.T) {
	base := "base000"
	r := makeReport()
	r.BaseRevision = &base
	r.ScanMode = "incremental"
	r.ChangedFiles = json.RawMessage(`["app/main.go"]`)

	resp := toReport(r)
	require.NotNil(t, resp.BaseRevision)
	assert.Equal(t, base, *resp.BaseRevision)
	assert.Equal(t, "incremental", resp.ScanMode)
	assert.Equal(t, []string{"app/main.go"}, resp.ChangedFiles)
}

func TestToReport_MapsErrorMessage(t *testing.T) {
	reason := "Internal error: could not store findings."
	r := makeReport()
	r.Status = "failed"
	r.ErrorMessage = &reason

	resp := toReport(r)
	require.NotNil(t, resp.ErrorMessage)
	assert.Equal(t, reason, *resp.ErrorMessage)

	completed := toReport(makeReport())
	assert.Nil(t, completed.ErrorMessage)
}

// incrementalHarness builds an ingest stack whose scanner emits two
// findings: fp-new (absent from the baseline) and fp-old (present in the
// baseline). hasBase controls whether a baseline report resolves.
func incrementalHarness(t *testing.T, hasBase bool) *Usecases {
	t.Helper()
	pr, rr, fr := makeTestRepos()
	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return makeProject(true), nil
	}
	rr.createFn = func(ctx context.Context, arg port.CreateReportInput) (port.Report, error) {
		return makeReport(), nil
	}
	rr.updateStatusFn = func(ctx context.Context, id, projectID, status string, totalFindings int32, errorMsg *string) (port.Report, error) {
		return makeReport(), nil
	}
	if hasBase {
		rr.byCommitFn = func(ctx context.Context, projectID, scanner, commit string) (port.CompletedReport, error) {
			return port.CompletedReport{ID: "22222222-2222-2222-2222-222222222222", ToolName: scanner, Completeness: "complete"}, nil
		}
	}
	fr.getByFingerprintFn = func(ctx context.Context, projectID, kind, fingerprint string) (port.Finding, error) {
		if fingerprint == "fp-old" {
			f := makeFinding(7)
			f.ID = "00000000-0000-0000-0000-000000000007"
			return f, nil
		}
		return port.Finding{}, port.ErrNotFound
	}
	fr.upsertFn = func(ctx context.Context, in port.UpsertFindingInput) (port.Finding, error) {
		return port.Finding{
			ID:          "finding-" + in.Fingerprint,
			ProjectID:   makeProject(true).ID,
			FindingKind: "sast",
			Fingerprint: in.Fingerprint,
		}, nil
	}
	fr.hasOccurrenceFn = func(ctx context.Context, findingID, reportID string) (bool, error) {
		return findingID == "finding-fp-old" && reportID == "22222222-2222-2222-2222-222222222222", nil
	}
	fr.createOccurrenceFn = func(ctx context.Context, arg port.OccurrenceInput) (port.Occurrence, error) {
		return port.Occurrence{}, nil
	}
	fr.upsertDimensionFn = func(ctx context.Context, arg port.DimensionInput) error {
		return nil
	}
	fr.updateAnalysisFn = func(ctx context.Context, arg port.UpdateAnalysisInput) (port.Finding, error) {
		return makeFinding(7), nil
	}

	reg := scanner.NewRegistry()
	require.NoError(t, reg.Register(&mockScanner{
		name:        "semgrep",
		incremental: true,
		parseFn: func(ctx context.Context, input []byte) (*domain.NormalizedReport, error) {
			return &domain.NormalizedReport{
				ContractVersion:    1,
				FingerprintVersion: 1,
				Completeness:       domain.CompletenessComplete,
				ScanType:           domain.ScanTypeFilesystem,
				Target:             &domain.TargetInfo{Kind: "repo", Identifier: "myapp"},
				Findings: []domain.NormalizedFinding{
					{Fingerprint: "fp-new", FindingKind: "sast", Title: "rule-a", Severity: domain.SeverityHigh, Score: 7.5},
					{Fingerprint: "fp-old", FindingKind: "sast", Title: "rule-b", Severity: domain.SeverityMedium, Score: 5.0},
				},
			}, nil
		},
	}))

	return New(Deps{
		Stores: &port.Stores{
			Projects:  pr,
			Reports:   rr,
			Findings:  fr,
			Targets:   stubTargetRepo(),
			Artifacts: stubArtifactRepo(),
		},
		Registry: reg,
	})
}

func TestIngestReport_IncrementalUnsupportedScannerFallsBack(t *testing.T) {
	uc, _, _, _ := revisionHarness(t, func(context.Context, string, string, string) (port.Finding, error) {
		return port.Finding{}, port.ErrNotFound
	})

	result, err := uc.IngestReport(context.Background(), IngestReportInput{
		ProjectSlug:  "my-app",
		Scanner:      "trivy",
		RawData:      json.RawMessage(`{"test": true}`),
		CommitSha:    "abc123",
		ScanMode:     "incremental",
		BaseRevision: "base000",
		ChangedFiles: []string{"app/main.go"},
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "full", result.ScanMode)
	assert.Contains(t, result.FallbackReason, "full scan")
}

func TestIngestReport_IncrementalNoBaselineFallsBack(t *testing.T) {
	uc := incrementalHarness(t, false)

	result, err := uc.IngestReport(context.Background(), IngestReportInput{
		ProjectSlug:  "my-app",
		Scanner:      "semgrep",
		RawData:      json.RawMessage(`{"test": true}`),
		CommitSha:    "abc123",
		ScanMode:     "incremental",
		BaseRevision: "missing-base",
		ChangedFiles: []string{"app/main.go"},
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "full", result.ScanMode)
	assert.Contains(t, result.FallbackReason, "baseline")
}

func TestIngestReport_IncrementalClassifiesIntroduced(t *testing.T) {
	uc := incrementalHarness(t, true)

	result, err := uc.IngestReport(context.Background(), IngestReportInput{
		ProjectSlug:  "my-app",
		Scanner:      "semgrep",
		RawData:      json.RawMessage(`{"test": true}`),
		CommitSha:    "abc123",
		ScanMode:     "incremental",
		BaseRevision: "base000",
		ChangedFiles: []string{"app/main.go"},
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "incremental", result.ScanMode)
	assert.Empty(t, result.FallbackReason)
	assert.Equal(t, 2, result.TotalFindings)
	assert.Equal(t, 1, result.IntroducedCount)
	assert.Equal(t, 1, result.PreExistingCount)
}

func TestIngestReport_GateIntroducedOnly(t *testing.T) {
	other := "99999999-9999-9999-9999-999999999999"
	build := func() (*Usecases, string) {
		pr, rr, fr := makeTestRepos()
		pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
			return makeProject(true), nil
		}
		rr.createFn = func(ctx context.Context, arg port.CreateReportInput) (port.Report, error) {
			return makeReport(), nil
		}
		rr.updateStatusFn = func(ctx context.Context, id, projectID, status string, totalFindings int32, errorMsg *string) (port.Report, error) {
			return makeReport(), nil
		}
		fr.getByFingerprintFn = func(context.Context, string, string, string) (port.Finding, error) {
			return port.Finding{}, port.ErrNotFound
		}
		fr.upsertFn = func(ctx context.Context, in port.UpsertFindingInput) (port.Finding, error) {
			return makeFinding(9), nil
		}
		fr.createOccurrenceFn = func(ctx context.Context, arg port.OccurrenceInput) (port.Occurrence, error) {
			return port.Occurrence{}, nil
		}
		fr.upsertDimensionFn = func(ctx context.Context, arg port.DimensionInput) error {
			return nil
		}
		fr.listGateCandidatesFn = func(ctx context.Context, projectID string, minRank int16) ([]port.GateCandidate, error) {
			return []port.GateCandidate{{
				Finding: port.Finding{
					ID: "00000000-0000-0000-0000-000000000099", ProjectID: makeProject(true).ID,
					CurrentSeverityRank: 4, FindingKind: "sca", Fingerprint: "fp-debt",
					CurrentTitle: "CVE-2023-0001", AnalysisState: "unanalyzed",
					IntroducedByReportID: &other,
				},
			}}, nil
		}

		reg := scanner.NewRegistry()
		require.NoError(t, reg.Register(&mockScanner{
			name: "trivy",
			parseFn: func(ctx context.Context, input []byte) (*domain.NormalizedReport, error) {
				return &domain.NormalizedReport{
					ContractVersion: 1, FingerprintVersion: 1,
					Completeness: domain.CompletenessComplete, ScanType: domain.ScanTypeImage,
					Target: &domain.TargetInfo{Kind: "container", Identifier: "myapp:latest"},
					Findings: []domain.NormalizedFinding{
						{Fingerprint: "fp-new", FindingKind: "sca", Title: "CVE-2024-1234", Severity: domain.SeverityHigh, Score: 7.5},
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
		return uc, makeReport().ID
	}

	full, _ := build()
	fullOut, err := full.IngestReport(context.Background(), IngestReportInput{
		ProjectSlug: "my-app", Scanner: "trivy", RawData: json.RawMessage(`{"test": true}`),
	})
	require.NoError(t, err)
	assert.True(t, fullOut.ThresholdBreached, "full gate sees pre-existing debt")

	introduced, currentReport := build()
	introducedOut, err := introduced.IngestReport(context.Background(), IngestReportInput{
		ProjectSlug: "my-app", Scanner: "trivy", RawData: json.RawMessage(`{"test": true}`),
		GateIntroducedOnly: true,
	})
	require.NoError(t, err)
	assert.False(t, introducedOut.ThresholdBreached, "introduced-only gate ignores debt from other reports")
	assert.Equal(t, currentReport, introducedOut.ReportID)
}

func TestIngestReport_DuplicateContentRejected(t *testing.T) {
	uc, rr, _, _ := revisionHarness(t, func(context.Context, string, string, string) (port.Finding, error) {
		return port.Finding{}, port.ErrNotFound
	})
	rr.findCompletedByHashFn = func(ctx context.Context, projectID, rawHash string) (string, error) {
		return "existing-report", nil
	}
	created := false
	rr.createFn = func(ctx context.Context, arg port.CreateReportInput) (port.Report, error) {
		created = true
		return makeReport(), nil
	}

	_, err := uc.IngestReport(context.Background(), IngestReportInput{
		ProjectSlug: "my-app", Scanner: "trivy", RawData: json.RawMessage(`{"test": true}`),
	})
	assert.ErrorIs(t, err, ErrDuplicateReport)
	assert.False(t, created, "duplicates must not write a processing row")
}

func TestIngestReport_DuplicateRaceCleansUp(t *testing.T) {
	uc, rr, _, _ := revisionHarness(t, func(context.Context, string, string, string) (port.Finding, error) {
		return port.Finding{}, port.ErrNotFound
	})
	rr.updateStatusFn = func(ctx context.Context, id, projectID, status string, totalFindings int32, errorMsg *string) (port.Report, error) {
		return port.Report{}, port.ErrDuplicateReport
	}
	var deletedID, deletedProject string
	rr.deleteReportFn = func(ctx context.Context, id, projectID string) error {
		deletedID, deletedProject = id, projectID
		return nil
	}

	_, err := uc.IngestReport(context.Background(), IngestReportInput{
		ProjectSlug: "my-app", Scanner: "trivy", RawData: json.RawMessage(`{"test": true}`),
	})
	assert.ErrorIs(t, err, ErrDuplicateReport)
	assert.Equal(t, makeReport().ID, deletedID, "the orphaned processing row must go")
	assert.Equal(t, makeProject(true).ID, deletedProject)
}

func TestIngestReport_MaterializesIntroducedFindings(t *testing.T) {
	pr, rr, fr := makeTestRepos()
	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return makeProject(true), nil
	}
	reportID := "report-1111"
	rr.createFn = func(ctx context.Context, arg port.CreateReportInput) (port.Report, error) {
		r := makeReport()
		r.ID = reportID
		return r, nil
	}
	rr.updateStatusFn = func(ctx context.Context, id, projectID, status string, totalFindings int32, errorMsg *string) (port.Report, error) {
		r := makeReport()
		r.ID = reportID
		return r, nil
	}

	// 3 findings:
	// fp-new: never seen before -> new
	// fp-regressed: state='fixed' -> regression
	// fp-old: exists and present in baseline -> pre-existing (not recorded in report_introduced_findings)
	baselineReportID := "baseline-2222"
	rr.byCommitFn = func(ctx context.Context, projectID, scanner, commit string) (port.CompletedReport, error) {
		return port.CompletedReport{ID: baselineReportID, ToolName: scanner, Completeness: "complete"}, nil
	}

	fr.listFindingsByFingerprintsFn = func(ctx context.Context, projectID, kind string, fps []string) ([]port.Finding, error) {
		return []port.Finding{
			{
				ID: "f-regressed", ProjectID: makeProject(true).ID,
				FindingKind: "sca", Fingerprint: "fp-regressed",
				CurrentTitle: "Regressed Flaw", CurrentSeverityRank: 4,
				State: "fixed",
			},
			{
				ID: "f-old", ProjectID: makeProject(true).ID,
				FindingKind: "sca", Fingerprint: "fp-old",
				CurrentTitle: "Old Flaw", CurrentSeverityRank: 3,
				State: "open",
			},
		}, nil
	}
	fr.listFindingIDsPresentInReportFn = func(ctx context.Context, repID string, findingIDs []string) ([]string, error) {
		assert.Equal(t, baselineReportID, repID)
		// Only f-old is in baseline
		return []string{"f-old"}, nil
	}
	fr.upsertFn = func(ctx context.Context, in port.UpsertFindingInput) (port.Finding, error) {
		return port.Finding{
			ID:          "upserted-" + in.Fingerprint,
			ProjectID:   makeProject(true).ID,
			FindingKind: "sca",
			Fingerprint: in.Fingerprint,
		}, nil
	}
	fr.createOccurrenceFn = func(ctx context.Context, arg port.OccurrenceInput) (port.Occurrence, error) {
		return port.Occurrence{}, nil
	}
	fr.upsertDimensionFn = func(ctx context.Context, arg port.DimensionInput) error {
		return nil
	}

	var recordedEntries []port.IntroducedFindingEntry
	var recordedReportID string
	var recordedBaseReportID *string
	fr.recordReportIntroducedFindingsFn = func(ctx context.Context, repID string, baseID *string, entries []port.IntroducedFindingEntry) error {
		recordedReportID = repID
		recordedBaseReportID = baseID
		recordedEntries = entries
		return nil
	}

	reg := scanner.NewRegistry()
	require.NoError(t, reg.Register(&mockScanner{
		name:        "trivy",
		incremental: true,
		parseFn: func(ctx context.Context, input []byte) (*domain.NormalizedReport, error) {
			return &domain.NormalizedReport{
				ContractVersion: 1, FingerprintVersion: 1,
				Completeness: domain.CompletenessComplete, ScanType: domain.ScanTypeImage,
				Target: &domain.TargetInfo{Kind: "container", Identifier: "myapp:latest"},
				Findings: []domain.NormalizedFinding{
					{Fingerprint: "fp-new", FindingKind: "sca", Title: "New Flaw", Severity: domain.SeverityHigh, Score: 7.5},
					{Fingerprint: "fp-regressed", FindingKind: "sca", Title: "Regressed Flaw", Severity: domain.SeverityCritical, Score: 9.8},
					{Fingerprint: "fp-old", FindingKind: "sca", Title: "Old Flaw", Severity: domain.SeverityHigh, Score: 7.0},
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

	out, err := uc.IngestReport(context.Background(), IngestReportInput{
		ProjectSlug:  "my-app",
		Scanner:      "trivy",
		RawData:      json.RawMessage(`{"test": true}`),
		ScanMode:     "incremental",
		BaseRevision: "main-sha",
	})
	require.NoError(t, err)
	assert.Equal(t, 3, out.TotalFindings)
	assert.Equal(t, 2, out.IntroducedCount)
	assert.Equal(t, 1, out.PreExistingCount)

	assert.Equal(t, reportID, recordedReportID)
	require.NotNil(t, recordedBaseReportID)
	assert.Equal(t, baselineReportID, *recordedBaseReportID)
	require.Len(t, recordedEntries, 2)
	assert.Equal(t, "upserted-fp-new", recordedEntries[0].FindingID)
	assert.Equal(t, "new", recordedEntries[0].ChangeType)
	assert.Equal(t, "upserted-fp-regressed", recordedEntries[1].FindingID)
	assert.Equal(t, "regression", recordedEntries[1].ChangeType)
}

func TestIngestReport_RegressionFailsIntroducedGate(t *testing.T) {
	pr, rr, fr := makeTestRepos()
	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return makeProject(true), nil
	}
	reportID := "report-1111"
	rr.createFn = func(ctx context.Context, arg port.CreateReportInput) (port.Report, error) {
		r := makeReport()
		r.ID = reportID
		return r, nil
	}
	rr.updateStatusFn = func(ctx context.Context, id, projectID, status string, totalFindings int32, errorMsg *string) (port.Report, error) {
		r := makeReport()
		r.ID = reportID
		return r, nil
	}

	fr.listFindingsByFingerprintsFn = func(ctx context.Context, projectID, kind string, fps []string) ([]port.Finding, error) {
		return []port.Finding{
			{
				ID: "f-regressed", ProjectID: makeProject(true).ID,
				FindingKind: "sca", Fingerprint: "fp-regressed",
				CurrentTitle: "Regressed Flaw", CurrentSeverityRank: 4,
				State: "fixed",
			},
		}, nil
	}
	fr.upsertFn = func(ctx context.Context, in port.UpsertFindingInput) (port.Finding, error) {
		return port.Finding{
			ID:          "f-regressed",
			ProjectID:   makeProject(true).ID,
			FindingKind: "sca",
			Fingerprint: in.Fingerprint,
		}, nil
	}
	fr.createOccurrenceFn = func(ctx context.Context, arg port.OccurrenceInput) (port.Occurrence, error) {
		return port.Occurrence{}, nil
	}
	fr.upsertDimensionFn = func(ctx context.Context, arg port.DimensionInput) error {
		return nil
	}
	fr.listIntroducedGateCandidatesFn = func(ctx context.Context, repID string, minRank int16) ([]port.GateCandidate, error) {
		assert.Equal(t, reportID, repID)
		return []port.GateCandidate{{
			Finding: port.Finding{
				ID: "f-regressed", ProjectID: makeProject(true).ID,
				CurrentSeverityRank: 4, FindingKind: "sca", Fingerprint: "fp-regressed",
				CurrentTitle: "Regressed Flaw", AnalysisState: "unanalyzed",
			},
		}}, nil
	}

	reg := scanner.NewRegistry()
	require.NoError(t, reg.Register(&mockScanner{
		name: "trivy",
		parseFn: func(ctx context.Context, input []byte) (*domain.NormalizedReport, error) {
			return &domain.NormalizedReport{
				ContractVersion: 1, FingerprintVersion: 1,
				Completeness: domain.CompletenessComplete, ScanType: domain.ScanTypeImage,
				Target: &domain.TargetInfo{Kind: "container", Identifier: "myapp:latest"},
				Findings: []domain.NormalizedFinding{
					{Fingerprint: "fp-regressed", FindingKind: "sca", Title: "Regressed Flaw", Severity: domain.SeverityCritical, Score: 9.8},
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

	out, err := uc.IngestReport(context.Background(), IngestReportInput{
		ProjectSlug:        "my-app",
		Scanner:            "trivy",
		RawData:            json.RawMessage(`{"test": true}`),
		GateIntroducedOnly: true,
	})
	require.NoError(t, err)
	assert.True(t, out.ThresholdBreached, "regressed vulnerability must block the introduced gate")
	assert.Equal(t, 1, out.IntroducedCount)
	assert.Equal(t, 0, out.PreExistingCount)
}
