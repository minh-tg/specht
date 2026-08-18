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

// selectiveScanner only matches data prefixed with matchPrefix.
type selectiveScanner struct {
	name        string
	matchPrefix []byte
}

func (s *selectiveScanner) Name() string { return s.name }

func (s *selectiveScanner) FindingKind() string { return "selective" }

func (s *selectiveScanner) Parse(_ context.Context, _ []byte) (*scanner.NormalizedReport, error) {
	return &scanner.NormalizedReport{ToolName: s.name}, nil
}

func (s *selectiveScanner) DetectFormat(data []byte) bool {
	return len(s.matchPrefix) > 0 && len(data) > 0 && len(data) >= len(s.matchPrefix) && string(data[:len(s.matchPrefix)]) == string(s.matchPrefix)
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

func TestRegistryRegisterOverwrite(t *testing.T) {
	r := scanner.NewRegistry()
	p1 := &testScanner{name: "overwrite-me"}
	p2 := &testScanner{name: "overwrite-me"}
	r.Register(p1)
	r.Register(p2)

	got, ok := r.Get("overwrite-me")
	require.True(t, ok)
	assert.Same(t, p2, got, "last registered scanner with same name should overwrite the previous")
}

func TestRegistryDetectMultipleMatches(t *testing.T) {
	r := scanner.NewRegistry()
	r.Register(&testScanner{name: "scanner-a"})
	r.Register(&testScanner{name: "scanner-b"})
	r.Register(&testScanner{name: "scanner-c"})

	got, ok := r.Detect([]byte("data"))
	require.True(t, ok)
	assert.Contains(t, []string{"scanner-a", "scanner-b", "scanner-c"}, got.Name())
}

func TestRegistryDetectWithSelectiveMatchers(t *testing.T) {
	// Test that a scanner matching only specific data works when it is the only match.
	r := scanner.NewRegistry()
	selective := &selectiveScanner{name: "selective", matchPrefix: []byte("secret")}
	r.Register(selective)

	got, ok := r.Detect([]byte("secret stuff"))
	require.True(t, ok)
	assert.Equal(t, "selective", got.Name())

	// Test that a non-matching prefix returns nothing (not detected by selective scanner).
	_, ok = r.Detect([]byte("other data"))
	assert.False(t, ok)

	// Separate registry: a generic (all-non-empty) scanner alone.
	r2 := scanner.NewRegistry()
	r2.Register(&testScanner{name: "generic"})

	got2, ok2 := r2.Detect([]byte("other data"))
	require.True(t, ok2)
	assert.Equal(t, "generic", got2.Name())
}

func TestSCAFingerprintEmbeddedSeparator(t *testing.T) {
	tests := []struct {
		name   string
		vulnID string
		purl   string
		want   scanner.Fingerprint
	}{
		{
			name:   "colon in purl",
			vulnID: "CVE-2024-1234",
			purl:   "pkg:github/foo/bar@1.0",
			want:   "CVE-2024-1234:pkg:github/foo/bar@1.0",
		},
		{
			name:   "colon in vulnID",
			vulnID: "GHSA:xxxx:yyyy",
			purl:   "pkg:npm/foo",
			want:   "GHSA:xxxx:yyyy:pkg:npm/foo",
		},
		{
			name:   "multiple colons",
			vulnID: "CVE-2024-1234",
			purl:   "pkg:oci/alpine:3.21",
			want:   "CVE-2024-1234:pkg:oci/alpine:3.21",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := scanner.SCAFingerprint(tt.vulnID, tt.purl)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestFingerprintType(t *testing.T) {
	// Fingerprint is a distinct named type, not just a string alias
	var fp scanner.Fingerprint = "custom-fp"
	assert.Equal(t, "custom-fp", string(fp))

	// Empty Fingerprint is valid
	var empty scanner.Fingerprint
	assert.Equal(t, "", string(empty))
	assert.Equal(t, 0, len(empty))
}
