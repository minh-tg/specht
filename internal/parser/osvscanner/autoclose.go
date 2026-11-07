package osvscanner

import "github.com/minh-tg/specht/internal/domain"

// SupportsAutoClose reports that a clean OSV-Scanner run closes findings. Its output
// does not say what the run looked at, so the run is taken at its word.
func (s *Scanner) SupportsAutoClose() bool { return true }

// AssumedCoverage takes a full OSV-Scanner run to have looked for what it reports.
func (s *Scanner) AssumedCoverage(*domain.NormalizedReport) []string { return []string{"sca"} }
