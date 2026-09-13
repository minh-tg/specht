package usecase

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xMinhx/specht/internal/domain"
	"github.com/xMinhx/specht/internal/port"
	"github.com/xMinhx/specht/internal/scanner"
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
	fr.upsertFn = func(ctx context.Context, _, _, _, _, _ string, _ int16, _ float64, _, _ time.Time) (port.Finding, error) {
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
	fr.upsertFn = func(ctx context.Context, _, _, fingerprint, _, _ string, _ int16, _ float64, _, _ time.Time) (port.Finding, error) {
		return port.Finding{
			ID:          "finding-" + fingerprint,
			ProjectID:   makeProject(true).ID,
			FindingKind: "sast",
			Fingerprint: fingerprint,
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
		fr.upsertFn = func(ctx context.Context, _, _, _, _, _ string, _ int16, _ float64, _, _ time.Time) (port.Finding, error) {
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
