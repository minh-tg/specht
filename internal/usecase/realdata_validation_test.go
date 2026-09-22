// full-loop validation: realistic fixture bytes travel through the
// REAL parser (via parser.Builtins, as the composition root registers them)
// into the REAL IngestReport use case, and the ingest response's
// ThresholdBreached must agree with a subsequent GetGateStatus call at the
// default high-severity floor. Stores are function mocks, but the findings
// mock retains upserts and its ListGateCandidates mimics the SQL prefilter
// (open/reopened state, severity-rank floor) so the gate evaluates the same
// candidate set the database would return.
package usecase

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xMinhx/specht/internal/parser"
	"github.com/xMinhx/specht/internal/parser/gitleaks"
	"github.com/xMinhx/specht/internal/port"
	"github.com/xMinhx/specht/internal/scanner"
)

type loopCase struct {
	scanner       string
	fixture       string // relative to internal/usecase
	totalFindings int
}

func TestRealDataFullLoopParity(t *testing.T) {
	cases := []loopCase{
		{"trivy", "../parser/trivy/testdata/multi-type-scan.json", 4},
		{"grype", "../parser/grype/testdata/grype-full.json", 105},
		{"semgrep", "../parser/semgrep/testdata/semgrep-sarif.json", 2},
		{"sbom", "../parser/sbom/testdata/cyclonedx.json", 0},
	}

	for _, tc := range cases {
		t.Run(tc.scanner, func(t *testing.T) {
			raw, err := os.ReadFile(tc.fixture)
			require.NoError(t, err)

			pr, rr, fr := makeTestRepos()
			pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
				return makeProject(true), nil
			}
			rr.createFn = func(ctx context.Context, arg port.CreateReportInput) (port.Report, error) {
				return makeReport(), nil
			}
			rr.updateStatusFn = func(ctx context.Context, id, projectID string, status string, totalFindings int32, errorMsg *string) (port.Report, error) {
				r := makeReport()
				r.Status = status
				return r, nil
			}

			var retained []port.Finding
			fr.getByFingerprintFn = func(ctx context.Context, projectID, findingKind, fingerprint string) (port.Finding, error) {
				return port.Finding{}, port.ErrNotFound
			}
			fr.upsertFn = func(ctx context.Context, in port.UpsertFindingInput) (port.Finding, error) {
				f := port.Finding{
					ID:        fmt.Sprintf("00000000-0000-0000-0000-%012d", len(retained)+1),
					ProjectID: in.ProjectID, FindingKind: in.FindingKind,
					Fingerprint: in.Fingerprint, CurrentTitle: in.Title,
					CurrentSeverityRank: in.SeverityRank,
					State:               "open", AnalysisState: "unanalyzed", GateEffect: "block",
				}
				retained = append(retained, f)
				return f, nil
			}
			fr.createOccurrenceFn = func(ctx context.Context, arg port.OccurrenceInput) (port.Occurrence, error) {
				return port.Occurrence{}, nil
			}
			fr.upsertDimensionFn = func(ctx context.Context, arg port.DimensionInput) error {
				return nil
			}
			fr.createEventFn = func(ctx context.Context, arg port.FindingEventInput) (port.FindingEvent, error) {
				return port.FindingEvent{}, nil
			}
			fr.hasDimensionFn = func(ctx context.Context, findingID, key string) (bool, error) {
				return false, nil
			}
			// Mimics the SQL candidate prefilter: open/reopened findings at
			// or above the severity-rank floor.
			fr.listGateCandidatesFn = func(ctx context.Context, projectID string, minSeverityRank int16) ([]port.GateCandidate, error) {
				var out []port.GateCandidate
				for _, f := range retained {
					if (f.State == "open" || f.State == "reopened") && f.CurrentSeverityRank >= minSeverityRank {
						out = append(out, port.GateCandidate{Finding: f, Reachability: "unknown"})
					}
				}
				return out, nil
			}

			inv := &mockInventoryRepo{}
			inv.upsertReportPackagesFn = func(ctx context.Context, reportID string, packages []port.PackageRef) error {
				return nil
			}

			reg := scanner.NewRegistry()
			for _, s := range parser.Builtins() {
				require.NoError(t, reg.Register(s))
			}

			uc := New(Deps{
				Stores: &port.Stores{
					Projects: pr, Reports: rr, Findings: fr,
					Targets: stubTargetRepo(), Artifacts: stubArtifactRepo(),
					Environments: &mockEnvironmentRepo{},
					Inventory:    inv,
					Waivers:      &mockWaiverRepo{},
				},
				Registry: reg,
			})

			result, err := uc.IngestReport(context.Background(), IngestReportInput{
				ProjectSlug: "my-app",
				Scanner:     tc.scanner,
				RawData:     raw,
			})
			require.NoError(t, err)
			require.Equal(t, tc.totalFindings, result.TotalFindings)
			require.Len(t, retained, tc.totalFindings, "every parsed finding must be upserted")

			status, err := uc.GetGateStatus(context.Background(), "my-app", 3)
			require.NoError(t, err)
			assert.Equal(t, result.ThresholdBreached, status.ThresholdBreached,
				"ingest response and GET gate must agree")
			t.Logf("%s: total=%d breached=%v blocking=%d",
				tc.scanner, result.TotalFindings, status.ThresholdBreached, status.BlockingCount)
		})
	}
}

func TestIngestReport_RedactsSecretRaw(t *testing.T) {
	raw, err := os.ReadFile("../parser/gitleaks/testdata/gitleaks.json")
	require.NoError(t, err)
	require.Contains(t, string(raw), "AKIAIOSFODNN7EXAMPLE")

	pr, rr, fr := makeTestRepos()
	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return makeProject(true), nil
	}
	var storedRaw []byte
	rr.createFn = func(ctx context.Context, arg port.CreateReportInput) (port.Report, error) {
		storedRaw = append([]byte{}, arg.RawData...)
		return makeReport(), nil
	}
	rr.updateStatusFn = func(ctx context.Context, id, projectID string, status string, totalFindings int32, errorMsg *string) (port.Report, error) {
		r := makeReport()
		r.Status = status
		return r, nil
	}
	fr.getByFingerprintFn = func(ctx context.Context, projectID, findingKind, fingerprint string) (port.Finding, error) {
		return port.Finding{}, port.ErrNotFound
	}
	fr.upsertFn = func(ctx context.Context, in port.UpsertFindingInput) (port.Finding, error) {
		return makeFinding(1), nil
	}
	fr.createOccurrenceFn = func(ctx context.Context, arg port.OccurrenceInput) (port.Occurrence, error) {
		return port.Occurrence{}, nil
	}
	fr.upsertDimensionFn = func(ctx context.Context, arg port.DimensionInput) error {
		return nil
	}
	fr.createEventFn = func(ctx context.Context, arg port.FindingEventInput) (port.FindingEvent, error) {
		return port.FindingEvent{}, nil
	}

	reg := scanner.NewRegistry()
	require.NoError(t, reg.Register(gitleaks.NewScanner()))

	uc := New(Deps{
		Stores: &port.Stores{
			Projects: pr, Reports: rr, Findings: fr,
			Targets: stubTargetRepo(), Artifacts: stubArtifactRepo(),
			Environments: &mockEnvironmentRepo{},
			Inventory:    &mockInventoryRepo{},
			Waivers:      &mockWaiverRepo{},
		},
		Registry: reg,
	})

	result, err := uc.IngestReport(context.Background(), IngestReportInput{
		ProjectSlug: "my-app",
		Scanner:     "gitleaks",
		RawData:     raw,
	})
	require.NoError(t, err)
	require.Equal(t, 3, result.TotalFindings)
	assert.NotContains(t, string(storedRaw), "AKIAIOSFODNN7EXAMPLE", "stored raw must not carry secret material")
	assert.NotContains(t, string(storedRaw), "sk-live-4eC39HqLyjWDarjtT1zdp7dc")
	assert.Contains(t, string(storedRaw), "[REDACTED]")
	assert.Contains(t, string(storedRaw), "aws-access-key", "provenance survives redaction")
}
