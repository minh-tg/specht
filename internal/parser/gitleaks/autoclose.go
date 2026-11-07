package gitleaks

import "github.com/minh-tg/specht/internal/domain"

// SupportsAutoClose reports that a clean Gitleaks run closes findings. Its output
// does not say what the run looked at, so the run is taken at its word.
func (s *Scanner) SupportsAutoClose() bool { return true }

// AssumedCoverage takes a full Gitleaks run to have looked for what it reports.
func (s *Scanner) AssumedCoverage(*domain.NormalizedReport) []string { return []string{"secret"} }
