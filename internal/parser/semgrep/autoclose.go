package semgrep

import "github.com/minh-tg/specht/internal/domain"

// formatKey and formatNative mark a report read from Semgrep's native JSON.
const (
	formatKey    = "semgrep_format"
	formatNative = "json"
)

// SupportsAutoClose reports that a clean Semgrep run closes findings. Its SARIF
// says which rules ran (see runProof). Its native JSON says neither rules nor
// files, so that run is taken at its word (see AssumedCoverage).
func (s *Scanner) SupportsAutoClose() bool { return true }

// AssumedCoverage takes a native JSON run to have looked for what it reports,
// unless it lists errors: the files Semgrep could not scan are missing from its
// results. SARIF states its own coverage and assumes nothing.
func (s *Scanner) AssumedCoverage(nr *domain.NormalizedReport) []string {
	if nr.ScanScope == nil || nr.ScanScope.Ext[formatKey] != formatNative {
		return nil
	}
	if _, failed := nr.ScanScope.Ext["semgrep_errors"]; failed {
		return nil
	}
	return []string{"sast"}
}
