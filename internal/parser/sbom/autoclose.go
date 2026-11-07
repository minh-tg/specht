package sbom

import "github.com/minh-tg/specht/internal/domain"

// SupportsAutoClose reports that an SBOM with a vulnerability analysis closes
// findings. A plain inventory never does.
func (s *Scanner) SupportsAutoClose() bool { return true }

// AssumedCoverage takes a file that carries a vulnerability analysis, such as
// Grype's CycloneDX output, to have looked for what it reports. An inventory
// vouches for nothing: it never looked for a vulnerability.
func (s *Scanner) AssumedCoverage(nr *domain.NormalizedReport) []string {
	if nr.ScanScope != nil && nr.ScanScope.Ext["sbom_vulnerabilities"] == "included" {
		return []string{"sca"}
	}
	return nil
}
