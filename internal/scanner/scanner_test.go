package scanner_test

import (
	"context"
	"io"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/vulnserve/vulnserve/internal/scanner"
)

type testParser struct {
	name      string
	scanTypes []scanner.ScanType
}

func (p *testParser) Name() string { return p.name }

func (p *testParser) ScanTypes() []scanner.ScanType { return p.scanTypes }

func (p *testParser) Parse(_ context.Context, _ io.Reader) (*scanner.NormalizedReport, error) {
	return &scanner.NormalizedReport{ScannerName: p.name}, nil
}

func (p *testParser) Detect(data []byte) bool {
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
			if int(tt.severity) != tt.want {
				t.Errorf("%s = %d, want %d", tt.name, tt.severity, tt.want)
			}
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
			if got != tt.want {
				t.Errorf("SCAFingerprint(%q, %q) = %q, want %q", tt.vulnID, tt.purl, got, tt.want)
			}
		})
	}
}

func TestNewRegistry(t *testing.T) {
	r := scanner.NewRegistry()
	if r == nil {
		t.Fatal("NewRegistry() returned nil")
	}
}

func TestRegistryRegisterGet(t *testing.T) {
	r := scanner.NewRegistry()
	p := &testParser{name: "test-parser", scanTypes: []scanner.ScanType{scanner.ScanTypeImage}}
	r.Register(p)

	got, ok := r.Get("test-parser")
	if !ok {
		t.Fatal("Get('test-parser') returned false")
	}
	if got.Name() != "test-parser" {
		t.Errorf("Get().Name() = %q, want 'test-parser'", got.Name())
	}

	scanTypes := got.ScanTypes()
	if diff := cmp.Diff(scanTypes, []scanner.ScanType{scanner.ScanTypeImage}); diff != "" {
		t.Errorf("ScanTypes() diff (-got +want):\n%s", diff)
	}
}

func TestRegistryGetUnknown(t *testing.T) {
	r := scanner.NewRegistry()
	_, ok := r.Get("nonexistent")
	if ok {
		t.Error("Get('nonexistent') returned true, want false")
	}
}

func TestRegistryDetect(t *testing.T) {
	r := scanner.NewRegistry()
	p := &testParser{name: "detect-parser"}
	r.Register(p)

	matched, ok := r.Detect([]byte("hello"))
	if !ok {
		t.Error("Detect() returned false, want true for non-empty data")
	}
	if matched.Name() != "detect-parser" {
		t.Errorf("Detect().Name() = %q, want 'detect-parser'", matched.Name())
	}
}

func TestRegistryDetectNoMatch(t *testing.T) {
	r := scanner.NewRegistry()
	_, ok := r.Detect([]byte("data"))
	if ok {
		t.Error("Detect() returned true, want false with empty registry")
	}
}

func TestRegistryDetectEmptyData(t *testing.T) {
	r := scanner.NewRegistry()
	r.Register(&testParser{name: "p"})
	_, ok := r.Detect([]byte{})
	if ok {
		t.Error("Detect() returned true for empty data, want false")
	}
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
			if string(tt.scanType) != tt.want {
				t.Errorf("ScanType(%s) = %q, want %q", tt.name, string(tt.scanType), tt.want)
			}
		})
	}
}
