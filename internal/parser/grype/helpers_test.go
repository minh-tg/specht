package grype

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/xMinhx/specht/internal/scanner"
)

func TestNormalizeGrypeSeverity(t *testing.T) {
	tests := []struct {
		input string
		want  scanner.Severity
	}{
		{"CRITICAL", scanner.SeverityCritical},
		{"critical", scanner.SeverityCritical},
		{"Critical", scanner.SeverityCritical},
		{"HIGH", scanner.SeverityHigh},
		{"MEDIUM", scanner.SeverityMedium},
		{"LOW", scanner.SeverityLow},
		{"", scanner.SeverityUnknown},
		{"UNKNOWN", scanner.SeverityUnknown},
		{"INFO", scanner.SeverityUnknown},
		{"NONE", scanner.SeverityUnknown},
		{"negligible", scanner.SeverityUnknown},
		{"random_string", scanner.SeverityUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizeGrypeSeverity(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestPickCVSS(t *testing.T) {
	t.Run("returns first with base score", func(t *testing.T) {
		cvssList := []grypeCVSS{
			{Version: "3.1", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", Metrics: grypeCVSSMetrics{BaseScore: 9.8}},
		}
		score, vec, ver := pickCVSS(cvssList)
		assert.Equal(t, 9.8, score)
		assert.Equal(t, "3.1", ver)
		assert.Contains(t, vec, "CVSS:3.1")
	})

	t.Run("returns zero when list empty", func(t *testing.T) {
		score, _, _ := pickCVSS(nil)
		assert.Equal(t, 0.0, score)
	})

	t.Run("skips entries with zero base score", func(t *testing.T) {
		cvssList := []grypeCVSS{
			{Version: "2.0", Metrics: grypeCVSSMetrics{BaseScore: 0}},
			{Version: "3.1", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", Metrics: grypeCVSSMetrics{BaseScore: 7.5}},
		}
		score, _, ver := pickCVSS(cvssList)
		assert.Equal(t, 7.5, score)
		assert.Equal(t, "3.1", ver)
	})
}

func TestExtractAliases(t *testing.T) {
	t.Run("extracts IDs from related vulnerabilities", func(t *testing.T) {
		related := []grypeRelatedVuln{
			{ID: "CVE-2021-3121"},
			{ID: "GHSA-xxxx-yyyy-zzzz"},
		}
		aliases := extractAliases(related)
		assert.Equal(t, []string{"CVE-2021-3121", "GHSA-xxxx-yyyy-zzzz"}, aliases)
	})

	t.Run("returns nil for empty list", func(t *testing.T) {
		aliases := extractAliases(nil)
		assert.Empty(t, aliases)
	})
}

func TestConvertEdgeCases(t *testing.T) {
	t.Run("empty document", func(t *testing.T) {
		nr := convert(grypeDoc{})
		require := assert.New(t)
		require.NotNil(nr)
		require.Empty(nr.Findings)
	})

	t.Run("match with no artifact purl uses empty purl in fingerprint", func(t *testing.T) {
		doc := grypeDoc{
			Matches: []grypeMatch{
				{
					Vulnerability: grypeVuln{
						ID:       "CVE-2024-0001",
						Severity: "HIGH",
					},
					Artifact: grypeArtifact{
						Name:    "some-pkg",
						Version: "1.0",
						Type:    "go-module",
						PURL:    "",
					},
				},
			},
		}
		nr := convert(doc)
		require := assert.New(t)
		require.Len(nr.Findings, 1)
		assert.Equal(t, "CVE-2024-0001:", nr.Findings[0].Fingerprint)
	})

	t.Run("match with no CVSS and no fix", func(t *testing.T) {
		doc := grypeDoc{
			Matches: []grypeMatch{
				{
					Vulnerability: grypeVuln{
						ID:       "CVE-2024-0002",
						Severity: "MEDIUM",
					},
					Artifact: grypeArtifact{
						Name: "some-pkg",
						PURL: "pkg:generic/some-pkg@1.0",
					},
				},
			},
		}
		nr := convert(doc)
		require := assert.New(t)
		require.Len(nr.Findings, 1)
		assert.Nil(t, nr.Findings[0].CVSS)
		assert.Nil(t, nr.Findings[0].Fix)
		assert.Equal(t, 0.0, nr.Findings[0].Score)
	})
}
