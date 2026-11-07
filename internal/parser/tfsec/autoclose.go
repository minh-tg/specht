package tfsec

import "github.com/minh-tg/specht/internal/domain"

// SupportsAutoClose reports that a clean tfsec run closes findings. Its output
// does not say what the run looked at, so the run is taken at its word.
func (s *Scanner) SupportsAutoClose() bool { return true }

// AssumedCoverage takes a full tfsec run to have looked for what it reports.
func (s *Scanner) AssumedCoverage(*domain.NormalizedReport) []string { return []string{"iac"} }
