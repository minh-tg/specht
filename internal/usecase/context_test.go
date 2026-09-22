// unit validation: owner binding on ingest and display-context
// attachment on finding detail, against function mocks.
package usecase

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xMinhx/specht/internal/auth"
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

// memberFindingDeps returns stores with a Findings mock plus a Projects
// mock reporting the caller as a member, so GetFinding passes the H1
// membership gate in tests that exercise display-context attachment.
func memberFindingDeps(fr *mockFindingRepo) *port.Stores {
	pr := &mockProjectRepo{}
	pr.isMemberFn = func(ctx context.Context, projectID, userID string) (bool, error) {
		return true, nil
	}
	return &port.Stores{Findings: fr, Projects: pr}
}

func memberSessionCtx() context.Context {
	return auth.ContextWithIdentity(context.Background(), &auth.Identity{
		UserID: "00000000-0000-0000-0000-000000000040",
		Role:   auth.RoleViewer,
	})
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

	uc := New(Deps{Stores: memberFindingDeps(fr)})
	finding, err := uc.GetFinding(memberSessionCtx(), "00000000-0000-0000-0000-000000000021")
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

	uc := New(Deps{Stores: memberFindingDeps(fr)})
	finding, err := uc.GetFinding(memberSessionCtx(), "00000000-0000-0000-0000-000000000021")
	require.NoError(t, err)
	assert.Nil(t, finding.Context, "missing context must be explicit nil, not zero fields")
}

func TestIngestReport_BindsDigestToArtifact(t *testing.T) {
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

	var got port.ArtifactInput
	ar := &mockArtifactRepo{}
	ar.upsertFn = func(ctx context.Context, arg port.ArtifactInput) (port.Artifact, error) {
		got = arg
		return port.Artifact{ID: "a1", ProjectID: arg.ProjectID, Name: arg.Name}, nil
	}
	inv := &mockInventoryRepo{}
	inv.upsertReportPackagesFn = func(ctx context.Context, reportID string, packages []port.PackageRef) error {
		return nil
	}

	uc := New(Deps{
		Stores: &port.Stores{
			Projects: pr, Reports: rr, Findings: fr,
			Targets: stubTargetRepo(), Artifacts: ar,
			Environments: &mockEnvironmentRepo{},
			Inventory:    inv,
			Waivers:      &mockWaiverRepo{},
		},
		Registry: contextTestRegistry(t),
	})

	_, err = uc.IngestReport(context.Background(), IngestReportInput{
		ProjectSlug:  "my-app",
		Scanner:      "trivy",
		RawData:      raw,
		ArtifactName: "myapp",
		ArtifactType: "container_image",
		Digest:       "sha256:abc123",
	})
	require.NoError(t, err)
	require.NotNil(t, got.Digest)
	assert.Equal(t, "sha256:abc123", *got.Digest)
	assert.Equal(t, "myapp", got.Name)
}

func TestGetFinding_RemediationFromSource(t *testing.T) {
	fr := &mockFindingRepo{}
	fr.getByIDFn = func(ctx context.Context, id string) (port.Finding, error) {
		return makeFindingRow(1), nil
	}
	fr.getDisplayContextFn = func(ctx context.Context, findingID string) (port.FindingDisplayContext, error) {
		return port.FindingDisplayContext{
			ToolName:        "trivy",
			LocationSummary: "main.tf:10",
			Metadata:        json.RawMessage(`{"specht":{"fix":{"Summary":"Upgrade to 1.2.4","URL":"https://advisory"},"code_location":{"File":"main.tf","StartLine":10,"EndLine":12},"resource":"aws_s3_bucket.data"}}`),
		}, nil
	}

	uc := New(Deps{Stores: memberFindingDeps(fr)})
	finding, err := uc.GetFinding(memberSessionCtx(), "00000000-0000-0000-0000-000000000021")
	require.NoError(t, err)
	require.NotNil(t, finding.Remediation)
	assert.Equal(t, "Upgrade to 1.2.4", finding.Remediation.Summary)
	assert.Equal(t, "https://advisory", finding.Remediation.URL)
	assert.Equal(t, "trivy", finding.Remediation.Source)
	assert.False(t, finding.Remediation.Fallback)
	require.NotNil(t, finding.Location)
	assert.Equal(t, "main.tf", finding.Location.File)
	assert.Equal(t, 10, finding.Location.StartLine)
	assert.Equal(t, "aws_s3_bucket.data", finding.Location.Resource)
	assert.Equal(t, "main.tf:10", finding.Location.Summary)
}

func TestGetFinding_RemediationFallback(t *testing.T) {
	fr := &mockFindingRepo{}
	fr.getByIDFn = func(ctx context.Context, id string) (port.Finding, error) {
		f := makeFindingRow(1)
		f.FindingKind = "sca"
		return f, nil
	}
	fr.getDisplayContextFn = func(ctx context.Context, findingID string) (port.FindingDisplayContext, error) {
		return port.FindingDisplayContext{ToolName: "grype", LocationSummary: "pkg:x"}, nil
	}

	uc := New(Deps{Stores: memberFindingDeps(fr)})
	finding, err := uc.GetFinding(memberSessionCtx(), "00000000-0000-0000-0000-000000000021")
	require.NoError(t, err)
	require.NotNil(t, finding.Remediation)
	assert.True(t, finding.Remediation.Fallback)
	assert.Contains(t, finding.Remediation.Summary, "fixed version")
}

func TestGetFinding_SuggestionFromDims(t *testing.T) {
	fr := &mockFindingRepo{}
	fr.getByIDFn = func(ctx context.Context, id string) (port.Finding, error) {
		f := makeFindingRow(1)
		f.FindingKind = "sca"
		return f, nil
	}
	fr.getDisplayContextFn = func(ctx context.Context, findingID string) (port.FindingDisplayContext, error) {
		return port.FindingDisplayContext{ToolName: "trivy"}, nil
	}
	fr.listDimensionsFn = func(ctx context.Context, findingID string) ([]port.FindingDimension, error) {
		return []port.FindingDimension{
			{Key: "package_name", Value: "curl"},
			{Key: "installed_version", Value: "7.88.1-r0"},
			{Key: "fixed_version", Value: "7.88.1-r1"},
		}, nil
	}

	uc := New(Deps{Stores: memberFindingDeps(fr)})
	finding, err := uc.GetFinding(memberSessionCtx(), "00000000-0000-0000-0000-000000000021")
	require.NoError(t, err)
	require.NotNil(t, finding.Suggestion)
	assert.Equal(t, "upgrade", finding.Suggestion.Action)
	assert.Equal(t, "curl", finding.Suggestion.Target)
	assert.Equal(t, "high", finding.Suggestion.Confidence)
	assert.Contains(t, finding.Suggestion.Detail, "7.88.1-r1")
}
