package nuclei

import "github.com/minh-tg/specht/internal/domain"

// SupportsAutoClose reports that a clean Nuclei run closes findings. Its output
// does not say what the run looked at, so the run is taken at its word.
func (s *Scanner) SupportsAutoClose() bool { return true }

// AssumedCoverage takes a full Nuclei run to have looked for what it reports,
// unless lines of its output could not be read: a run killed mid-write leaves a
// truncated line, and what that line reported must not read as gone.
func (s *Scanner) AssumedCoverage(nr *domain.NormalizedReport) []string {
	if nr.ScanScope != nil && nr.ScanScope.Ext["skipped_lines"] != "" {
		return nil
	}
	return []string{"dast"}
}
