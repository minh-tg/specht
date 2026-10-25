package trivy

// SupportsAutoClose reports that a Trivy report can prove a fix: it names the
// result classes it scanned, and a finding of a scanned kind that is absent
// from a complete scan is closed.
func (s *Scanner) SupportsAutoClose() bool { return true }
