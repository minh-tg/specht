package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/domain"
	"github.com/minh-tg/specht/internal/scanner"
)

// A clean scan closes findings for every scanner. A project can keep one manual.
func TestEveryScannerSupportsAutoClose(t *testing.T) {
	for _, s := range Builtins() {
		assert.True(t, scanner.SupportsAutoClose(s), s.Descriptor().Name)
	}
}

func builtin(t *testing.T, name string) scanner.Scanner {
	t.Helper()
	for _, s := range Builtins() {
		if s.Descriptor().Name == name {
			return s
		}
	}
	require.Failf(t, "no such scanner", "%s", name)
	return nil
}

func TestAssumedCoverageTakesAFullRunAtItsWord(t *testing.T) {
	for name, kind := range map[string]string{
		"gitleaks": "secret", "tfsec": "iac", "nuclei": "dast",
		"osv-scanner": "sca", "dependency-check": "sca",
	} {
		nr := &domain.NormalizedReport{Completeness: domain.CompletenessUnknown}
		scanner.ApplyAssumedCoverage(builtin(t, name), nr)
		assert.Equal(t, domain.CompletenessComplete, nr.Completeness, name)
		assert.Equal(t, []string{kind}, nr.CoveredFindingKinds, name)
	}
}

func TestAssumedCoverageLeavesStatedCompletenessAlone(t *testing.T) {
	partial := &domain.NormalizedReport{Completeness: domain.CompletenessPartial}
	scanner.ApplyAssumedCoverage(builtin(t, "gitleaks"), partial)
	assert.Equal(t, domain.CompletenessPartial, partial.Completeness)
	assert.Empty(t, partial.CoveredFindingKinds)
}

func TestAssumedCoverageSkipsScannersThatProveTheirCoverage(t *testing.T) {
	for _, name := range []string{"trivy", "grype", "checkov", "sarif"} {
		nr := &domain.NormalizedReport{Completeness: domain.CompletenessUnknown}
		scanner.ApplyAssumedCoverage(builtin(t, name), nr)
		assert.Equal(t, domain.CompletenessUnknown, nr.Completeness, name)
	}
}

func TestAssumedCoverageForSBOMNeedsAVulnerabilityAnalysis(t *testing.T) {
	sbom := builtin(t, "sbom")

	inventory := &domain.NormalizedReport{Completeness: domain.CompletenessUnknown}
	scanner.ApplyAssumedCoverage(sbom, inventory)
	assert.Equal(t, domain.CompletenessUnknown, inventory.Completeness)

	analysed := &domain.NormalizedReport{
		Completeness: domain.CompletenessUnknown,
		ScanScope:    &domain.ScanScope{Ext: map[string]string{"sbom_vulnerabilities": "included"}},
	}
	scanner.ApplyAssumedCoverage(sbom, analysed)
	assert.Equal(t, domain.CompletenessComplete, analysed.Completeness)
	assert.Equal(t, []string{"sca"}, analysed.CoveredFindingKinds)
}

func TestAssumedCoverageForSemgrep(t *testing.T) {
	semgrep := builtin(t, "semgrep")
	native := func(ext map[string]string) *domain.NormalizedReport {
		return &domain.NormalizedReport{
			Completeness: domain.CompletenessUnknown,
			ScanScope:    &domain.ScanScope{Ext: ext},
		}
	}

	clean := native(map[string]string{"semgrep_format": "json"})
	scanner.ApplyAssumedCoverage(semgrep, clean)
	assert.Equal(t, domain.CompletenessComplete, clean.Completeness, "native JSON is taken at its word")

	failed := native(map[string]string{"semgrep_format": "json", "semgrep_errors": "1"})
	scanner.ApplyAssumedCoverage(semgrep, failed)
	assert.Equal(t, domain.CompletenessUnknown, failed.Completeness, "a run with errors missed files")

	sarif := &domain.NormalizedReport{Completeness: domain.CompletenessUnknown}
	scanner.ApplyAssumedCoverage(semgrep, sarif)
	assert.Equal(t, domain.CompletenessUnknown, sarif.Completeness, "SARIF states its own coverage")
}
