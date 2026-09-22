package sbom

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/domain"
)

func TestDescriptor_InventoryOnly(t *testing.T) {
	d := NewScanner().Descriptor()
	assert.Equal(t, "sbom", d.Name)
	assert.Empty(t, d.FindingKinds, "SBOMs carry inventory, not findings")
	assert.True(t, d.ProvidesPackages)
	assert.Contains(t, d.ScanTypes, domain.ScanTypeSBOM)
	assert.True(t, d.SupportsAutoDetection)
}

func TestDetectFormat(t *testing.T) {
	s := NewScanner()
	cdx, err := os.ReadFile("testdata/cyclonedx.json")
	require.NoError(t, err)
	spdx, err := os.ReadFile("testdata/spdx.json")
	require.NoError(t, err)
	assert.True(t, s.DetectFormat(cdx))
	assert.True(t, s.DetectFormat(spdx))
	assert.False(t, s.DetectFormat([]byte(`[{"Target":"x"}]`)))
	assert.False(t, s.DetectFormat([]byte(`not json`)))
}

func TestParseCycloneDX(t *testing.T) {
	data, err := os.ReadFile("testdata/cyclonedx.json")
	require.NoError(t, err)
	rep, err := NewScanner().Parse(context.Background(), data)
	require.NoError(t, err)
	assert.Empty(t, rep.Findings)
	require.Len(t, rep.Packages, 4)
	assert.Equal(t, domain.ScanTypeSBOM, rep.ScanType)
	assert.Equal(t, domain.CompletenessComplete, rep.Completeness)
	require.NotNil(t, rep.Target)
	assert.Equal(t, "myapp@1.2.3", rep.Target.Identifier)

	lodash := rep.Packages[0]
	assert.Equal(t, "pkg:npm/lodash@4.17.20", lodash.PURL)
	assert.Equal(t, "npm", lodash.Ecosystem)
	assert.Equal(t, "lodash", lodash.Name)
	assert.Equal(t, "4.17.20", lodash.Version)

	gin := rep.Packages[1]
	assert.Equal(t, "golang", gin.Ecosystem)

	bare := rep.Packages[2]
	assert.Equal(t, "internal-tool", bare.Name)
	assert.Empty(t, bare.PURL)
	assert.Empty(t, bare.Ecosystem)
	assert.Equal(t, "unnamed-tool", rep.Packages[3].Name)
}

func TestParseCycloneDXSkipsNamelessComponent(t *testing.T) {
	rep, err := NewScanner().Parse(context.Background(), []byte(`{"bomFormat":"CycloneDX","components":[{"type":"library","name":""}]}`))
	require.NoError(t, err)
	assert.Empty(t, rep.Packages)
}

func TestParseSPDX(t *testing.T) {
	data, err := os.ReadFile("testdata/spdx.json")
	require.NoError(t, err)
	rep, err := NewScanner().Parse(context.Background(), data)
	require.NoError(t, err)
	assert.Empty(t, rep.Findings)
	require.Len(t, rep.Packages, 2, "document stub and versionless stub skipped")
	assert.Equal(t, "myapp-1.2.3", rep.Target.Identifier)

	lodash := rep.Packages[0]
	assert.Equal(t, "pkg:npm/lodash@4.17.20", lodash.PURL)
	assert.Equal(t, "npm", lodash.Ecosystem)

	openssl := rep.Packages[1]
	assert.Equal(t, "openssl", openssl.Name)
	assert.Equal(t, "3.0.12", openssl.Version)
	assert.Empty(t, openssl.PURL)
}

func TestParse_Errors(t *testing.T) {
	s := NewScanner()
	_, err := s.Parse(context.Background(), []byte(`{invalid`))
	require.Error(t, err)
	_, err = s.Parse(context.Background(), []byte(`{"name":"no envelope markers"}`))
	require.ErrorContains(t, err, "unrecognized document")
}

func TestParse_EmptyComponents(t *testing.T) {
	rep, err := NewScanner().Parse(context.Background(),
		[]byte(`{"bomFormat":"CycloneDX","components":[]}`))
	require.NoError(t, err)
	assert.Empty(t, rep.Packages)
	assert.Empty(t, rep.Findings)
}
