package domain

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalizeArtifactType(t *testing.T) {
	for in, want := range map[string]string{
		"container_image":     "container_image",
		"container-image":     "container_image",
		" Container_Image ":   "container_image",
		"repository-snapshot": "repository_snapshot",
		"sarif":               "sarif",
	} {
		got, ok := NormalizeArtifactType(in)
		assert.True(t, ok, in)
		assert.Equal(t, want, got, in)
	}
	for _, in := range []string{"", "image", "repository", "docker", "iac"} {
		_, ok := NormalizeArtifactType(in)
		assert.False(t, ok, in)
	}
}

func TestNormalizeTargetKind_StaysInsideTheCheckVocabulary(t *testing.T) {
	allowed := []string{"repo", "service", "container_image", "filesystem", "iac_stack", "package"}
	for _, tc := range []struct {
		kind     string
		scanType ScanType
		want     string
	}{
		{"container_image", ScanTypeImage, "container_image"},
		{"repository", ScanTypeRepository, "repo"},
		{"cyclonedx", ScanTypeSBOM, "package"},
		{"vm", ScanTypeImage, "filesystem"},
		{"iac", ScanTypeIaC, "iac_stack"},
		{"terraform", ScanTypeIaC, "iac_stack"},
		{"", ScanTypeImage, "container_image"},
		{"", ScanTypeLockfile, "package"},
		{"", ScanTypeDAST, "service"},
		{"", ScanTypeFilesystem, "filesystem"},
		{"something-new", "", "filesystem"},
	} {
		got := NormalizeTargetKind(tc.kind, tc.scanType)
		assert.Equal(t, tc.want, got, "%q/%q", tc.kind, tc.scanType)
		assert.True(t, slices.Contains(allowed, got), got)
	}
}

func TestArtifactTypeForScan_StaysInsideTheCheckVocabulary(t *testing.T) {
	for _, st := range []ScanType{ScanTypeImage, ScanTypeFilesystem, ScanTypeRepository, ScanTypeIaC, ScanTypeSBOM, ScanTypeLockfile} {
		got := ArtifactTypeForScan(st)
		assert.True(t, slices.Contains(ArtifactTypes, got), "%s maps to %q", st, got)
	}
	assert.Equal(t, "container_image", ArtifactTypeForScan(ScanTypeImage))
	assert.Equal(t, "", ArtifactTypeForScan(ScanTypeDAST), "a DAST scan has no artifact type")
	assert.Equal(t, "", ArtifactTypeForScan("unknown"))
}
