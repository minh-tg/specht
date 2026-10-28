package semgrep

// SupportsAutoClose reports that a semgrep report cannot prove a fix. Its SARIF
// lists the rules it loaded but not the files it scanned, and a rule proves a
// finding absent only for files its own run listed, so a clean Semgrep scan
// leaves the finding open. The native JSON format lists no rules at all.
func (s *Scanner) SupportsAutoClose() bool { return false }
