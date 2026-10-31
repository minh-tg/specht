package client

import (
	"strconv"
	"strings"
)

// DeclaredScanFilter builds the scan_filter of an ingest request from what the
// caller said about the scan, or returns nil when the scan was not filtered.
//
// severities is a comma-separated list and fixableOnly is nil when the caller
// gave no answer. Trivy and Grype write nothing about --severity or
// --ignore-unfixed into their reports, so for the trivy scanner an absent
// answer falls back to Trivy's own TRIVY_SEVERITY and TRIVY_IGNORE_UNFIXED
// variables, which the step that ran the scan usually sets. A filter already on
// the request (from an input envelope) is kept where the caller says nothing.
func DeclaredScanFilter(scanner, severities string, fixableOnly *bool, existing *ScanFilter, getenv func(string) string) *ScanFilter {
	filter := ScanFilter{}
	if existing != nil {
		filter = *existing
	}
	if strings.EqualFold(scanner, "trivy") {
		if severities == "" {
			severities = getenv("TRIVY_SEVERITY")
		}
		if fixableOnly == nil {
			if v, err := strconv.ParseBool(strings.TrimSpace(getenv("TRIVY_IGNORE_UNFIXED"))); err == nil {
				fixableOnly = &v
			}
		}
	}
	if list := splitList(severities); len(list) > 0 {
		filter.Severities = list
	}
	if fixableOnly != nil {
		filter.FixableOnly = *fixableOnly
	}
	if len(filter.Severities) == 0 && !filter.FixableOnly {
		return nil
	}
	return &filter
}

// splitList splits a comma-separated list and drops blanks.
func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}
