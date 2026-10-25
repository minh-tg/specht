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

func TestArtifactTypeForScan_StaysInsideTheCheckVocabulary(t *testing.T) {
	for _, st := range []ScanType{ScanTypeImage, ScanTypeFilesystem, ScanTypeRepository, ScanTypeIaC, ScanTypeSBOM, ScanTypeLockfile} {
		got := ArtifactTypeForScan(st)
		assert.True(t, slices.Contains(ArtifactTypes, got), "%s maps to %q", st, got)
	}
	assert.Equal(t, "container_image", ArtifactTypeForScan(ScanTypeImage))
	assert.Equal(t, "", ArtifactTypeForScan(ScanTypeDAST), "a DAST scan has no artifact type")
	assert.Equal(t, "", ArtifactTypeForScan("unknown"))
}
