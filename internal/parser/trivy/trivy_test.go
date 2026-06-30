package trivy_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/vulnserve/vulnserve/internal/parser/trivy"
	"github.com/vulnserve/vulnserve/internal/scanner"
)

func TestName(t *testing.T) {
	p := trivy.NewParser()
	if p.Name() != "trivy" {
		t.Errorf("expected 'trivy', got %q", p.Name())
	}
}

func TestScanTypes(t *testing.T) {
	p := trivy.NewParser()
	types := p.ScanTypes()
	if len(types) == 0 {
		t.Fatal("expected at least one scan type")
	}
}

func TestDetect_ValidInput(t *testing.T) {
	p := trivy.NewParser()
	data, err := os.ReadFile("testdata/alpine-scan.json")
	if err != nil {
		t.Fatal(err)
	}
	if !p.Detect(data) {
		t.Error("expected Detect to return true for valid trivy JSON")
	}
}

func TestDetect_InvalidInput(t *testing.T) {
	p := trivy.NewParser()
	if p.Detect([]byte(`{}`)) {
		t.Error("expected Detect to return false for non-trivy JSON")
	}
	if p.Detect([]byte(`not json`)) {
		t.Error("expected Detect to return false for invalid JSON")
	}
}

func TestParse_AlpineScan(t *testing.T) {
	p := trivy.NewParser()
	f, err := os.Open("testdata/alpine-scan.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	report, err := p.Parse(context.Background(), f)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	if report.ScannerName != "trivy" {
		t.Errorf("expected ScannerName 'trivy', got %q", report.ScannerName)
	}

	if report.Target == nil {
		t.Fatal("expected Target to be set")
	}
	if report.Target.Identifier != "alpine:3.20 (alpine 3.20.3)" {
		t.Errorf("unexpected target: %q", report.Target.Identifier)
	}

	if len(report.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(report.Findings))
	}

	tests := []struct {
		name          string
		fingerprint   string
		severity      scanner.Severity
		score         float64
		findingKind   string
		fixedVersion  string
	}{
		{
			name:          "first finding should be CVE-2024-9143",
			fingerprint:   "CVE-2024-9143:pkg:apk/alpine/libcrypto3@3.3.2-r0?arch=aarch64&distro=3.20.3",
			severity:      scanner.SeverityLow,
			score:         4.0,
			findingKind:   "sca",
			fixedVersion:  "3.3.2-r1",
		},
		{
			name:          "second finding should be CVE-2024-8888",
			fingerprint:   "CVE-2024-8888:pkg:apk/alpine/libssl3@3.3.2-r0?arch=aarch64&distro=3.20.3",
			severity:      scanner.SeverityHigh,
			score:         6.0,
			findingKind:   "sca",
			fixedVersion:  "3.3.2-r1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			found := false
			for _, f := range report.Findings {
				if f.Fingerprint == tt.fingerprint {
					found = true
					if f.Severity != tt.severity {
						t.Errorf("severity = %d, want %d", f.Severity, tt.severity)
					}
					if f.FindingKind != tt.findingKind {
						t.Errorf("findingKind = %q, want %q", f.FindingKind, tt.findingKind)
					}
					if f.Score != tt.score {
						t.Errorf("score = %f, want %f", f.Score, tt.score)
					}
					break
				}
			}
			if !found {
				t.Errorf("finding with fingerprint %q not found", tt.fingerprint)
			}
		})
	}
}

func TestParse_EmptyScan(t *testing.T) {
	p := trivy.NewParser()
	f, err := os.Open("testdata/empty-scan.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	report, err := p.Parse(context.Background(), f)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	if len(report.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(report.Findings))
	}
}

func TestParse_MultiTypeScan(t *testing.T) {
	p := trivy.NewParser()
	f, err := os.Open("testdata/multi-type-scan.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	report, err := p.Parse(context.Background(), f)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	if len(report.Findings) != 4 {
		t.Fatalf("expected 4 findings (sca + sca + iac + secret), got %d", len(report.Findings))
	}

	kinds := make(map[string]int)
	for _, f := range report.Findings {
		kinds[f.FindingKind]++
	}

	if kinds["sca"] != 2 {
		t.Errorf("expected 2 sca, got %d", kinds["sca"])
	}
	if kinds["iac"] != 1 {
		t.Errorf("expected 1 iac, got %d", kinds["iac"])
	}
	if kinds["secret"] != 1 {
		t.Errorf("expected 1 secret, got %d", kinds["secret"])
	}
}

func TestParse_InvalidJSON(t *testing.T) {
	p := trivy.NewParser()
	_, err := p.Parse(context.Background(), strings.NewReader(`not json`))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}
