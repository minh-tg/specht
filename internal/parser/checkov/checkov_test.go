package checkov_test

import (
	"context"
	_ "embed"
	"testing"

	"github.com/minh-tg/specht/internal/domain"

	"github.com/minh-tg/specht/internal/parser/checkov"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//go:embed testdata/checkov-terraform.json
var checkovTerraformFixture []byte

//go:embed testdata/checkov-empty.json
var checkovEmptyFixture []byte

//go:embed testdata/checkov-kubernetes.json
var checkovKubernetesFixture []byte

//go:embed testdata/checkov-cloudformation.json
var checkovCloudformationFixture []byte

func TestDetectFormat(t *testing.T) {
	s := checkov.NewScanner()

	assert.True(t, s.DetectFormat(checkovTerraformFixture),
		"should detect checkov terraform format")
	assert.False(t, s.DetectFormat([]byte(`{}`)),
		"should not detect empty json as checkov")
	assert.False(t, s.DetectFormat([]byte(`{"check_type":""}`)),
		"should not detect when check_type is empty")
}

func TestName(t *testing.T) {
	assert.Equal(t, "checkov", checkov.NewScanner().Descriptor().Name)
}

func TestFindingKind(t *testing.T) {
	kinds := []string{}
	for _, k := range checkov.NewScanner().Descriptor().FindingKinds {
		kinds = append(kinds, string(k))
	}
	assert.Equal(t, []string{"iac"}, kinds)
}

func TestParseReturnsReport(t *testing.T) {
	s := checkov.NewScanner()
	report, err := s.Parse(context.Background(), checkovTerraformFixture)
	require.NoError(t, err)
	require.NotNil(t, report)

	assert.Equal(t, domain.ScanTypeIaC, report.ScanType)
	require.NotNil(t, report.Target)
	assert.Equal(t, "terraform", report.Target.Kind)

	require.Len(t, report.Findings, 3)
}

func TestParseFindingFields(t *testing.T) {
	s := checkov.NewScanner()
	report, err := s.Parse(context.Background(), checkovTerraformFixture)
	require.NoError(t, err)
	require.Len(t, report.Findings, 3)

	f := report.Findings[0]

	assert.Equal(t, "iac", f.FindingKind)
	assert.Equal(t, "Ensure the key vault is recoverable", f.Title)
	assert.Equal(t, "Ensure the key vault is recoverable", f.Description)
	assert.Equal(t, domain.SeverityHigh, f.Severity)
	assert.Equal(t, "/terraform/main.tf:1", f.Location)
	assert.Equal(t, "azurerm_key_vault.main", f.Resource)
	assert.Equal(t, "iac:CKV_AZURE_41:azurerm_key_vault.main:/terraform/main.tf", f.Fingerprint)

	require.NotNil(t, f.Fix)
	assert.Equal(t, "https://docs.bridgecrew.io/docs/ensure-the-key-vault-is-recoverable", f.Fix.URL)

	require.NotNil(t, f.CodeLocation)
	assert.Equal(t, "/terraform/main.tf", f.CodeLocation.File)
	assert.Equal(t, 1, f.CodeLocation.StartLine)
	assert.Equal(t, 16, f.CodeLocation.EndLine)
}

func TestParseDimensions(t *testing.T) {
	s := checkov.NewScanner()
	report, err := s.Parse(context.Background(), checkovTerraformFixture)
	require.NoError(t, err)
	require.Len(t, report.Findings, 3)

	f := report.Findings[0]
	dims := f.Dimensions
	require.Len(t, dims, 2)
	assert.Equal(t, "rule_id", dims[0].Key)
	assert.Equal(t, "CKV_AZURE_41", dims[0].Value)
	assert.Equal(t, "resource", dims[1].Key)
	assert.Equal(t, "azurerm_key_vault.main", dims[1].Value)
}

func TestParseSetsDisplay(t *testing.T) {
	s := checkov.NewScanner()
	report, err := s.Parse(context.Background(), checkovTerraformFixture)
	require.NoError(t, err)

	f := report.Findings[0]
	assert.Equal(t, "/terraform/main.tf", f.Extensions["file"])
	assert.Equal(t, "azurerm_key_vault.main", f.Resource)
	assert.Contains(t, f.Extensions, "guideline")
}

func TestParseEmptyResults(t *testing.T) {
	s := checkov.NewScanner()
	report, err := s.Parse(context.Background(), checkovEmptyFixture)
	require.NoError(t, err)
	require.NotNil(t, report)
	assert.Empty(t, report.Findings)
}

func TestSeverityMapping(t *testing.T) {
	s := checkov.NewScanner()
	report, err := s.Parse(context.Background(), checkovTerraformFixture)
	require.NoError(t, err)
	require.Len(t, report.Findings, 3)

	assert.Equal(t, domain.SeverityHigh, report.Findings[0].Severity, "HIGH")
	assert.Equal(t, domain.SeverityMedium, report.Findings[1].Severity, "MEDIUM")
	assert.Equal(t, domain.SeverityMedium, report.Findings[2].Severity, "MEDIUM")
}

func TestParseInvalidJSON(t *testing.T) {
	s := checkov.NewScanner()
	_, err := s.Parse(context.Background(), []byte(`not json`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "checkov")
}

func TestParseKubernetesFramework(t *testing.T) {
	s := checkov.NewScanner()
	report, err := s.Parse(context.Background(), checkovKubernetesFixture)
	require.NoError(t, err)
	require.NotNil(t, report.Target)
	assert.Equal(t, "kubernetes", report.Target.Kind)
	require.Len(t, report.Findings, 2)
	assert.Equal(t, "Deployment.default.web", report.Findings[0].Resource)
	assert.Equal(t, []string{"BC_K8S_21"}, report.Findings[0].Aliases)
	assert.Equal(t, "BC_K8S_21", report.Findings[0].Extensions["bc_check_id"])
	assert.Empty(t, report.Findings[1].Aliases, "absent bc id yields no alias")
}

func TestParseCloudformationFramework(t *testing.T) {
	s := checkov.NewScanner()
	report, err := s.Parse(context.Background(), checkovCloudformationFixture)
	require.NoError(t, err)
	require.NotNil(t, report.Target)
	assert.Equal(t, "cloudformation", report.Target.Kind)
	require.Len(t, report.Findings, 1)
	assert.Equal(t, "AWS::S3::Bucket.DataBucket", report.Findings[0].Resource)
	assert.Equal(t, []string{"BC_AWS_19"}, report.Findings[0].Aliases)
}
