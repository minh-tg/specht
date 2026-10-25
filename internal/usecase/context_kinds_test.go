package usecase

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/minh-tg/specht/internal/domain"
	"github.com/minh-tg/specht/internal/port"
)

func TestResolveArtifact_StoresTypesTheCheckAccepts(t *testing.T) {
	tests := []struct {
		name     string
		input    IngestReportInput
		scanType domain.ScanType
		want     string
	}{
		{"image scan without a type", IngestReportInput{ArtifactName: "registry/app"}, domain.ScanTypeImage, "container_image"},
		{"repository scan without a type", IngestReportInput{ArtifactName: "app"}, domain.ScanTypeRepository, "repository_snapshot"},
		{"iac scan without a type", IngestReportInput{ArtifactName: "infra"}, domain.ScanTypeIaC, "iac_stack"},
		{"lockfile scan without a type", IngestReportInput{ArtifactName: "go.sum"}, domain.ScanTypeLockfile, "filesystem"},
		{"hyphenated request type", IngestReportInput{ArtifactName: "registry/app", ArtifactType: "container-image"}, domain.ScanTypeFilesystem, "container_image"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var got string
			ar := &mockArtifactRepo{}
			ar.upsertFn = func(ctx context.Context, in port.ArtifactInput) (port.Artifact, error) {
				got = in.ArtifactType
				return port.Artifact{ID: "a1"}, nil
			}
			uc := New(Deps{Stores: &port.Stores{Artifacts: ar}})
			id := uc.resolveArtifact(context.Background(), makeProject(true), tc.input, &domain.NormalizedReport{ScanType: tc.scanType}, "")
			assert.Equal(t, "a1", id)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestResolveTarget_StoresKindsTheCheckAccepts(t *testing.T) {
	var got string
	tr := &mockTargetRepo{}
	tr.upsertFn = func(ctx context.Context, projectID, name, kind, locator, owner string) (port.Target, error) {
		got = kind
		return port.Target{ID: "t1"}, nil
	}
	uc := New(Deps{Stores: &port.Stores{Targets: tr}})
	nr := &domain.NormalizedReport{ScanType: domain.ScanTypeIaC, Target: &domain.TargetInfo{Identifier: "main.tf", Kind: "iac"}}
	id, identifier := uc.resolveTarget(context.Background(), makeProject(true), IngestReportInput{}, nr)
	assert.Equal(t, "t1", id)
	assert.Equal(t, "main.tf", identifier)
	assert.Equal(t, "iac_stack", got)
	assert.Equal(t, "iac", nr.Target.Kind, "the parser kind feeds the scope hash and stays untouched")
}

func TestResolveArtifact_SkipsTypesOutsideTheVocabulary(t *testing.T) {
	ar := &mockArtifactRepo{} // an Upsert call returns an error and an empty id
	uc := New(Deps{Stores: &port.Stores{Artifacts: ar}})
	for _, tc := range []struct {
		input    IngestReportInput
		scanType domain.ScanType
	}{
		{IngestReportInput{ArtifactName: "https://app.example"}, domain.ScanTypeDAST},
		{IngestReportInput{ArtifactName: "app", ArtifactType: "docker"}, domain.ScanTypeImage},
	} {
		ar.upsertFn = func(ctx context.Context, in port.ArtifactInput) (port.Artifact, error) {
			t.Errorf("upsert called with type %q", in.ArtifactType)
			return port.Artifact{}, nil
		}
		assert.Empty(t, uc.resolveArtifact(context.Background(), makeProject(true), tc.input, &domain.NormalizedReport{ScanType: tc.scanType}, ""))
	}
}
