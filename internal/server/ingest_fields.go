package server

import (
	"fmt"
	"strings"
	"unicode"
)

// Limits on the metadata of an ingest request. They are far above anything a
// real CI run sends and far below what makes a row, a log line or a check
// summary unreadable.
const (
	maxCommitShaBytes     = 64
	maxBranchBytes        = 255
	maxEnvironmentBytes   = 64
	maxTextFieldBytes     = 255
	maxChangedFiles       = 5000
	maxChangedFileBytes   = 1024
	msgNULNotAllowed      = "must not contain a NUL character"
	msgControlNotAllowed  = "must not contain control characters"
	msgCommitShaCharacter = "may only contain letters, digits, '.', '_' and '-'"
)

// invalidField returns the JSON name of the first metadata field of the request
// that the server refuses, and what is wrong with it; both are empty when every
// field is acceptable. It runs before anything is written, so a refused request
// leaves no environment, target or artifact row behind.
//
// A NUL is refused on its own message because PostgreSQL rejects it in text and
// dropping it could make one name another. Other control characters would let a
// field forge log lines or markdown in a check summary. raw_data is handled on
// its own, because scanners can legitimately quote a NUL.
func (r ingestRequest) invalidField() (field, problem string) {
	for _, f := range []struct {
		name, value string
		max         int
	}{
		{"project", r.Project, maxTextFieldBytes},
		{"scanner", r.Scanner, maxTextFieldBytes},
		{"scanner_version", r.ScannerVersion, maxTextFieldBytes},
		{"parser_version", r.ParserVersion, maxTextFieldBytes},
		{"branch", r.Branch, maxBranchBytes},
		{"commit_sha", r.CommitSha, maxCommitShaBytes},
		{"base_revision", r.BaseRevision, maxTextFieldBytes},
		{"scan_mode", r.ScanMode, maxTextFieldBytes},
		{"gate_severity", r.GateSeverity, maxTextFieldBytes},
		{"gate_status", r.GateStatus, maxTextFieldBytes},
		{"environment", r.Environment, maxEnvironmentBytes},
		{"owner", r.Owner, maxTextFieldBytes},
		{"digest", r.Digest, maxTextFieldBytes},
		{"artifact_name", r.ArtifactName, maxTextFieldBytes},
		{"artifact_version", r.ArtifactVersion, maxTextFieldBytes},
		{"artifact_type", r.ArtifactType, maxTextFieldBytes},
	} {
		if problem := textProblem(f.value, f.max); problem != "" {
			return f.name, problem
		}
	}
	if i := strings.IndexFunc(r.CommitSha, func(c rune) bool { return !commitShaRune(c) }); i >= 0 {
		return "commit_sha", msgCommitShaCharacter
	}
	if len(r.ChangedFiles) > maxChangedFiles {
		return "changed_files", fmt.Sprintf("may list at most %d files", maxChangedFiles)
	}
	for _, file := range r.ChangedFiles {
		if problem := textProblem(file, maxChangedFileBytes); problem != "" {
			return "changed_files", "entries " + problem
		}
	}
	return "", ""
}

// textProblem says why s is not an acceptable metadata value, or returns ""
// when it is: at most max bytes and no control characters.
func textProblem(s string, max int) string {
	if strings.ContainsRune(s, 0) {
		return msgNULNotAllowed
	}
	if len(s) > max {
		return fmt.Sprintf("must be at most %d bytes", max)
	}
	if strings.IndexFunc(s, unicode.IsControl) >= 0 {
		return msgControlNotAllowed
	}
	return ""
}

// commitShaRune reports whether c may appear in a commit_sha: hex digits, and
// the letters and punctuation of tags and short refs CI systems send in its
// place.
func commitShaRune(c rune) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '.' || c == '_' || c == '-'
}
