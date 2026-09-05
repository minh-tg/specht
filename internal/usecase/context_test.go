// unit validation: owner binding on ingest and display-context
// attachment on finding detail, against function mocks.
package usecase

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xMinhx/specht/internal/parser"
	"github.com/xMinhx/specht/internal/port"
	"github.com/xMinhx/specht/internal/scanner"
)

func contextTestRegistry(t *testing.T) *scanner.Registry {
	t.Helper()
	reg := scanner.NewRegistry()
	for _, s := range parser.Builtins() {
		require.NoError(t, reg.Register(s))
	}
	return reg
}

func TestIngestReport_BindsOwnerToTarget(t *testing.T) {
	raw, err := os.ReadFile("../parser/trivy/testdata/multi-type-scan.json")
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
	fr.getByFingerprintFn = func(ctx context.Context, projectID, findingKind, fingerprint string) (port.Finding, error) {
		return port.Finding{}, port.ErrNotFound
	}
	fr.upsertFn = func(ctx context.Context, projectID, findingKind, fingerprint, title, severity string, severityRank int16, score float64, firstSeen, lastSeen time.Time) (port.Finding, error) {
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

	var gotOwner, gotTarget string
	tr := &mockTargetRepo{}
	tr.upsertFn = func(ctx context.Context, projectID, name, kind, locator, owner string) (port.Target, error) {
		gotTarget, gotOwner = name, owner
		return port.Target{ID: "t1", ProjectID: projectID, Name: name, Kind: kind}, nil
	}
	inv := &mockInventoryRepo{}
	inv.upsertReportPackagesFn = func(ctx context.Context, reportID string, packages []port.PackageRef) error {
		return nil
	}

	uc := New(Deps{
		Stores: &port.Stores{
			Projects: pr, Reports: rr, Findings: fr,
			Targets: tr, Artifacts: stubArtifactRepo(),
			Environments: &mockEnvironmentRepo{},
			Inventory:    inv,
			Waivers:      &mockWaiverRepo{},
		},
		Registry: contextTestRegistry(t),
	})

	result, err := uc.IngestReport(context.Background(), IngestReportInput{
		ProjectSlug: "my-app",
		Scanner:     "trivy",
		RawData:     raw,
		Owner:       "team-a",
	})
	require.NoError(t, err)
	require.Equal(t, 4, result.TotalFindings)
	assert.NotEmpty(t, gotTarget, "trivy fixture must resolve a target")
	assert.Equal(t, "team-a", gotOwner, "supplied owner must reach the target upsert")
}

func TestGetFinding_WithContext(t *testing.T) {
	fr := &mockFindingRepo{}
	fr.getByIDFn = func(ctx context.Context, id string) (port.Finding, error) {
		return makeFindingRow(1), nil
	}
	fr.getDisplayContextFn = func(ctx context.Context, findingID string) (port.FindingDisplayContext, error) {
		return port.FindingDisplayContext{
			TargetName: "alpine:3.20", TargetKind: "container_image",
			TargetOwner: "team-a", EnvironmentName: "production",
			Branch: "main", CommitSha: "abc123",
		}, nil
	}

	uc := New(Deps{Stores: &port.Stores{Findings: fr}})
	finding, err := uc.GetFinding(context.Background(), "00000000-0000-0000-0000-000000000021")
	require.NoError(t, err)
	require.NotNil(t, finding.Context)
	assert.Equal(t, "alpine:3.20", finding.Context.TargetName)
	assert.Equal(t, "team-a", finding.Context.TargetOwner)
	assert.Equal(t, "production", finding.Context.EnvironmentName)
	assert.Equal(t, "main", finding.Context.Branch)
	assert.Equal(t, "abc123", finding.Context.CommitSha)
}

func TestGetFinding_NoContext(t *testing.T) {
	fr := &mockFindingRepo{}
	fr.getByIDFn = func(ctx context.Context, id string) (port.Finding, error) {
		return makeFindingRow(1), nil
	}
	fr.getDisplayContextFn = func(ctx context.Context, findingID string) (port.FindingDisplayContext, error) {
		return port.FindingDisplayContext{}, port.ErrNotFound
	}

	uc := New(Deps{Stores: &port.Stores{Findings: fr}})
	finding, err := uc.GetFinding(context.Background(), "00000000-0000-0000-0000-000000000021")
	require.NoError(t, err)
	assert.Nil(t, finding.Context, "missing context must be explicit nil, not zero fields")
}
