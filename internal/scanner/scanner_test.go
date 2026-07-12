package scanner_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xMinhx/specht/internal/scanner"
)

type testScanner struct {
	name string
}

func (s *testScanner) Name() string { return s.name }

func (s *testScanner) FindingKind() string { return "test" }

func (s *testScanner) Parse(_ context.Context, _ []byte) (*scanner.NormalizedReport, error) {
	return &scanner.NormalizedReport{ToolName: s.name}, nil
}

func (s *testScanner) DetectFormat(data []byte) bool {
	return len(data) > 0
}

func TestSeverityValues(t *testing.T) {
	tests := []struct {
		severity scanner.Severity
		name     string
		want     int
	}{
		{scanner.SeverityUnknown, "unknown", 0},
		{scanner.SeverityLow, "low", 1},
		{scanner.SeverityMedium, "medium", 2},
		{scanner.SeverityHigh, "high", 3},
		{scanner.SeverityCritical, "critical", 4},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, int(tt.severity))
		})
	}
}

func TestSCAFingerprint(t *testing.T) {
	tests := []struct {
		name   string
		vulnID string
		purl   string
		want   scanner.Fingerprint
	}{
		{"standard", "CVE-2024-1234", "pkg:npm/foo@1.0.0", "CVE-2024-1234:pkg:npm/foo@1.0.0"},
		{"empty vuln id", "", "pkg:npm/foo", ":pkg:npm/foo"},
		{"empty purl", "CVE-2024-1234", "", "CVE-2024-1234:"},
		{"both empty", "", "", ":"},
		{"ghsa format", "GHSA-xxxx-xxxx-xxxx", "pkg:golang/foo/bar", "GHSA-xxxx-xxxx-xxxx:pkg:golang/foo/bar"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := scanner.SCAFingerprint(tt.vulnID, tt.purl)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestNewRegistry(t *testing.T) {
	r := scanner.NewRegistry()
	require.NotNil(t, r)
}

func TestRegistryRegisterGet(t *testing.T) {
	r := scanner.NewRegistry()
	p := &testScanner{name: "test-parser"}
	r.Register(p)

	got, ok := r.Get("test-parser")
	require.True(t, ok)
	assert.Equal(t, "test-parser", got.Name())
}

func TestRegistryGetUnknown(t *testing.T) {
	r := scanner.NewRegistry()
	_, ok := r.Get("nonexistent")
	assert.False(t, ok)
}

func TestRegistryDetect(t *testing.T) {
	r := scanner.NewRegistry()
	p := &testScanner{name: "detect-parser"}
	r.Register(p)

	matched, ok := r.Detect([]byte("hello"))
	require.True(t, ok)
	assert.Equal(t, "detect-parser", matched.Name())
}

func TestRegistryDetectNoMatch(t *testing.T) {
	r := scanner.NewRegistry()
	_, ok := r.Detect([]byte("data"))
	assert.False(t, ok)
}

func TestRegistryDetectEmptyData(t *testing.T) {
	r := scanner.NewRegistry()
	r.Register(&testScanner{name: "p"})
	_, ok := r.Detect([]byte{})
	assert.False(t, ok)
}

func TestScanTypeConstants(t *testing.T) {
	tests := []struct {
		scanType scanner.ScanType
		name     string
		want     string
	}{
		{scanner.ScanTypeImage, "image", "image"},
		{scanner.ScanTypeFilesystem, "filesystem", "filesystem"},
		{scanner.ScanTypeRepository, "repository", "repository"},
		{scanner.ScanTypeIaC, "iac", "iac"},
		{scanner.ScanTypeSBOM, "sbom", "sbom"},
		{scanner.ScanTypeLockfile, "lockfile", "lockfile"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, string(tt.scanType))
		})
	}
}
