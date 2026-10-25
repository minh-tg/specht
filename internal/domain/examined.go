package domain

import (
	"sort"
	"strings"
)

// Examination keys are the strings a parser writes into
// NormalizedReport.ExaminedKeys to prove, finding by finding, what the
// scanner's own output shows it looked for. The auto-fix step and the report
// delete match them against stored findings in SQL
// (report_examined_finding), so the spelling here is a storage format.

const (
	// ExaminedFilesScope asks the matcher to require the finding's file to be
	// named by an ExaminedFile key as well as its rule. A run that lists the
	// files it scanned sets it, so a rule that ran elsewhere proves nothing
	// about a file the run never listed.
	ExaminedFilesScope = "scope:files"

	// MaxExaminedKeys bounds the keys one report may carry. A report with more
	// proves nothing, because a hostile document must not grow a row without
	// limit.
	MaxExaminedKeys = 20000

	maxExaminedKeyBytes = 600
)

// ExaminedFingerprint proves the report checked the finding with this
// fingerprint, as a passed check does.
func ExaminedFingerprint(fingerprint string) string { return "fp:" + fingerprint }

// ExaminedRule proves the report ran a rule over the finding kind.
func ExaminedRule(kind, ruleID string) string { return "rule:" + kind + ":" + ruleID }

// ExaminedFile proves the report scanned a file.
func ExaminedFile(path string) string { return "file:" + path }

// NormalizeExaminedKeys sorts and de-duplicates keys and drops empty or
// oversized ones. More than MaxExaminedKeys returns nil: a report whose proof
// does not fit proves nothing.
func NormalizeExaminedKeys(keys []string) []string {
	seen := make(map[string]struct{}, len(keys))
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		if strings.TrimSpace(k) == "" || len(k) > maxExaminedKeyBytes {
			continue
		}
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, k)
	}
	if len(out) > MaxExaminedKeys {
		return nil
	}
	sort.Strings(out)
	return out
}
