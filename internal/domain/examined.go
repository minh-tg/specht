package domain

import (
	"sort"
	"strconv"
	"strings"
)

// Examination keys are the strings a parser writes into
// NormalizedReport.ExaminedKeys to prove, finding by finding, what the
// scanner's own output shows it looked for. The auto-fix step and the report
// delete match them against stored findings in SQL
// (report_examined_finding), so the spelling here is a storage format.

const (
	// MaxExaminedKeys bounds the keys one report may carry. A report with more
	// proves nothing, because a hostile document must not grow a row without
	// limit.
	MaxExaminedKeys = 20000

	maxExaminedKeyBytes = 600
)

// ExaminedFingerprint proves the report checked the finding with this
// fingerprint, as a passed check does.
func ExaminedFingerprint(fingerprint string) string { return "fp:" + fingerprint }

// ExaminedRunRule says run number run of the report ran a rule over the
// finding kind. It proves nothing alone: the matcher also needs an
// ExaminedRunFile key of the same run for the finding's file, so a rule only
// vouches for the files its own run scanned.
func ExaminedRunRule(run int, kind, ruleID string) string {
	return "run:" + strconv.Itoa(run) + ":rule:" + kind + ":" + ruleID
}

// ExaminedRunFile says run number run of the report scanned a file.
func ExaminedRunFile(run int, path string) string {
	return "run:" + strconv.Itoa(run) + ":file:" + path
}

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
