package grype

// SupportsAutoClose reports that a grype report can prove a fix: it closes a
// finding by absence when the report itself shows the finding was looked for.
func (s *Scanner) SupportsAutoClose() bool { return true }
