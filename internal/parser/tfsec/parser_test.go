package tfsec

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/domain"
)

func TestDescriptor(t *testing.T) {
	d := NewScanner().Descriptor()
	assert.Equal(t, "tfsec", d.Name)
	assert.Equal(t, []string{"iac"}, []string{string(d.FindingKinds[0])})
	assert.False(t, d.ProvidesPackages)
}

func TestDetectFormat(t *testing.T) {
	data, err := os.ReadFile("testdata/tfsec.json")
	require.NoError(t, err)
	assert.True(t, NewScanner().DetectFormat(data))
	assert.False(t, NewScanner().DetectFormat([]byte(`{"check_type":"terraform"}`)))
}

func TestParseSkipsNonFailures(t *testing.T) {
	data, err := os.ReadFile("testdata/tfsec.json")
	require.NoError(t, err)
	rep, err := NewScanner().Parse(context.Background(), data)
	require.NoError(t, err)
	require.Len(t, rep.Findings, 2, "passed check must not become a finding")
	assert.Equal(t, domain.ScanTypeIaC, rep.ScanType)

	s3 := rep.Findings[0]
	assert.Equal(t, "iac:aws-s3-enable-versioning:aws_s3_bucket.data", s3.Fingerprint)
	assert.Equal(t, "iac", s3.FindingKind)
	assert.Equal(t, domain.SeverityHigh, s3.Severity)
	assert.Equal(t, "main.tf:10", s3.Location)
	assert.Equal(t, "aws_s3_bucket.data", s3.Resource)
	require.NotNil(t, s3.Fix)
	assert.Equal(t, "Enable versioning on the S3 bucket.", s3.Fix.Summary)
	assert.Equal(t, "https://tfsec.dev/docs/aws/s3/enable-versioning", s3.Fix.URL)
	require.NotNil(t, s3.CodeLocation)
	assert.Contains(t, s3.Description, "Data loss")

	variable := rep.Findings[1]
	assert.Equal(t, domain.SeverityMedium, variable.Severity)
	assert.Equal(t, "var.db_password", variable.Resource)
}

func TestParseInvalidJSON(t *testing.T) {
	_, err := NewScanner().Parse(context.Background(), []byte(`not json`))
	require.Error(t, err)
}
