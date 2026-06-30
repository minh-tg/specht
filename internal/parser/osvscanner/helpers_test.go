package osvscanner

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vulnserve/vulnserve/internal/scanner"
)

func TestSeverityFromScore(t *testing.T) {
	tests := []struct {
		score float64
		want  scanner.Severity
	}{
		{10.0, scanner.SeverityCritical},
		{9.0, scanner.SeverityCritical},
		{8.9, scanner.SeverityHigh},
		{7.0, scanner.SeverityHigh},
		{6.9, scanner.SeverityMedium},
		{4.0, scanner.SeverityMedium},
		{3.9, scanner.SeverityLow},
		{0.1, scanner.SeverityLow},
		{0.0, scanner.SeverityUnknown},
		{-1.0, scanner.SeverityUnknown},
	}
	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			got := severityFromScore(tt.score)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestNormalizeOSVSeverity(t *testing.T) {
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
		{"random", scanner.SeverityUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizeOSVSeverity(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParseCVSSScore(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantOk  bool
		wantMin float64
	}{
		{"full v4 vector", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", true, 9.0},
		{"full v3 vector", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", true, 9.0},
		{"full v2 vector", "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P", true, 7.0},
		{"bare v2 vector", "AV:N/AC:L/Au:N/C:P/I:N/A:N", true, 5.0},
		{"numeric score", "7.5", true, 7.5},
		{"numeric score zero", "0.0", true, 0.0},
		{"empty string", "", false, 0},
		{"garbage", "not-a-vector", false, 0},
		{"garbage with uuid prefix", "uuid:abc-123", false, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _, ok := parseCVSSScore(tt.input)
			assert.Equal(t, tt.wantOk, ok)
			if tt.wantOk {
				assert.GreaterOrEqual(t, got, tt.wantMin)
			}
		})
	}
}

func TestLooksLikeCVSSv2Vector(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"AV:N/AC:L/Au:N/C:P/I:P/A:P", true},
		{"AV:A/AC:M/Au:S/C:C/I:C/A:C", true},
		{"AV:L/AC:H/Au:M/C:N/I:N/A:N", true},
		{"CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P", false},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", false},
		{"not-a-vector", false},
		{"", false},
		{"RANDOM:text", false},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := looksLikeCVSSv2Vector(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestExtractSeverity(t *testing.T) {
	empty := osvSeverity{}
	v4Crit := osvSeverity{Type: "CVSS_V4", Score: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}
	v3Crit := osvSeverity{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
	v2High := osvSeverity{Type: "CVSS_V2", Score: "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P"}
	v2Bare := osvSeverity{Type: "CVSS_V2", Score: "AV:N/AC:L/Au:N/C:P/I:N/A:N"}
	numericMed := osvSeverity{Type: "CVSS_V3", Score: "5.5"}
	numericLow := osvSeverity{Type: "CVSS_V3", Score: "1.2"}
	dbSpecificHigh := osvDBSpecific{Severity: "HIGH"}

	tests := []struct {
		name string
		vuln osvVuln
		want scanner.Severity
	}{
		{"db specific overrides", osvVuln{DatabaseSpecific: &dbSpecificHigh, Severity: []osvSeverity{v4Crit}}, scanner.SeverityHigh},
		{"empty severities", osvVuln{}, scanner.SeverityUnknown},
		{"no match", osvVuln{Severity: []osvSeverity{empty}}, scanner.SeverityUnknown},
		{"cvss v4 critical", osvVuln{Severity: []osvSeverity{v4Crit}}, scanner.SeverityCritical},
		{"cvss v3 critical", osvVuln{Severity: []osvSeverity{v3Crit}}, scanner.SeverityCritical},
		{"cvss v2 high", osvVuln{Severity: []osvSeverity{v2High}}, scanner.SeverityHigh},
		{"cvss v2 bare medium", osvVuln{Severity: []osvSeverity{v2Bare}}, scanner.SeverityMedium},
		{"numeric medium", osvVuln{Severity: []osvSeverity{numericMed}}, scanner.SeverityMedium},
		{"numeric low", osvVuln{Severity: []osvSeverity{numericLow}}, scanner.SeverityLow},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractSeverity(tt.vuln)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestExtractScore(t *testing.T) {
	v4Score := osvSeverity{Type: "CVSS_V4", Score: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}
	v3Score := osvSeverity{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
	v2Score := osvSeverity{Type: "CVSS_V2", Score: "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P"}
	v2BareScore := osvSeverity{Type: "CVSS_V2", Score: "AV:N/AC:L/Au:N/C:P/I:N/A:N"}
	lowScore := osvSeverity{Type: "CVSS_V3", Score: "1.2"}

	tests := []struct {
		name string
		vuln osvVuln
		want float64
	}{
		{"prefers v4 over v3 and v2", osvVuln{Severity: []osvSeverity{v4Score, v3Score, v2Score}}, 9.3},
		{"prefers v3 over v2", osvVuln{Severity: []osvSeverity{v3Score, v2Score}}, 9.8},
		{"falls back to v2", osvVuln{Severity: []osvSeverity{v2Score}}, 7.5},
		{"v2 bare vector", osvVuln{Severity: []osvSeverity{v2BareScore}}, 5.0},
		{"low numeric score", osvVuln{Severity: []osvSeverity{lowScore}}, 1.2},
		{"empty severity", osvVuln{}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractScore(tt.vuln)
			assert.Equal(t, tt.want, got)
		})
	}
}
