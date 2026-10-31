package domain

import (
	"fmt"
	"sort"
	"strings"
)

// ScanSeverities lists the severity names a scan filter accepts, lowest rank
// first. They are the spellings finding rows and the reports_filter_severities
// CHECK use.
var ScanSeverities = []string{"unknown", "low", "medium", "high", "critical"}

// ScanFilter is what the uploader says the scanner left out on purpose, such as
// Trivy --severity HIGH,CRITICAL or --ignore-unfixed. Scanner output records no
// such flag, so a filtered report looks like a full one. A report closes only
// the findings inside its filter.
type ScanFilter struct {
	// Severities are the severities the scan kept, lowercase, de-duplicated and
	// sorted by rank. Empty means no severity filter.
	Severities []string
	// FixableOnly is set when the scan kept only findings with a fix available.
	FixableOnly bool
}

// IsZero reports whether the filter leaves every finding inside it.
func (f ScanFilter) IsZero() bool { return len(f.Severities) == 0 && !f.FixableOnly }

// NormalizeScanFilter lowercases and de-duplicates the severities and orders
// them by rank. A value outside ScanSeverities is an error naming it.
func NormalizeScanFilter(severities []string, fixableOnly bool) (ScanFilter, error) {
	rank := make(map[string]int, len(ScanSeverities))
	for i, s := range ScanSeverities {
		rank[s] = i
	}
	seen := make(map[string]struct{}, len(severities))
	out := make([]string, 0, len(severities))
	for _, s := range severities {
		name := strings.ToLower(strings.TrimSpace(s))
		if _, ok := rank[name]; !ok {
			return ScanFilter{}, fmt.Errorf("severity %q must be one of %s", s, strings.Join(ScanSeverities, ", "))
		}
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	sort.Slice(out, func(i, j int) bool { return rank[out[i]] < rank[out[j]] })
	if len(out) == 0 {
		out = nil
	}
	return ScanFilter{Severities: out, FixableOnly: fixableOnly}, nil
}
