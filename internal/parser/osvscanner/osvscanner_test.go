package osvscanner_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/vulnserve/vulnserve/internal/parser/osvscanner"
	"github.com/vulnserve/vulnserve/internal/scanner"
)

func TestName(t *testing.T) {
	p := osvscanner.NewParser()
	if p.Name() != "osv-scanner" {
		t.Errorf("expected 'osv-scanner', got %q", p.Name())
	}
}

func TestScanTypes(t *testing.T) {
	p := osvscanner.NewParser()
	types := p.ScanTypes()
	if len(types) == 0 {
		t.Fatal("expected at least one scan type")
	}
}

func TestDetect_ValidInput(t *testing.T) {
	p := osvscanner.NewParser()
	data, err := os.ReadFile("testdata/go-scan.json")
	if err != nil {
		t.Fatal(err)
	}
	if !p.Detect(data) {
		t.Error("expected Detect to return true for valid osv-scanner JSON")
	}
}

func TestDetect_InvalidInput(t *testing.T) {
	p := osvscanner.NewParser()
	if p.Detect([]byte(`{}`)) {
		t.Error("expected Detect to return false for non-osv-scanner JSON")
	}
	if p.Detect([]byte(`not json`)) {
		t.Error("expected Detect to return false for invalid JSON")
	}
}

func TestParse_GoScan(t *testing.T) {
	p := osvscanner.NewParser()
	f, err := os.Open("testdata/go-scan.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	report, err := p.Parse(context.Background(), f)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	if report.ScannerName != "osv-scanner" {
		t.Errorf("expected ScannerName 'osv-scanner', got %q", report.ScannerName)
	}

	if report.Target == nil {
		t.Fatal("expected Target to be set")
	}

	if len(report.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(report.Findings))
	}

	finding := report.Findings[0]

	expectedFP := "GHSA-c3h9-896r-86jm:pkg:golang/github.com/gogo/protobuf"
	if finding.Fingerprint != expectedFP {
		t.Errorf("fingerprint = %q, want %q", finding.Fingerprint, expectedFP)
	}

	if finding.FindingKind != "sca" {
		t.Errorf("findingKind = %q, want 'sca_vulnerability'", finding.FindingKind)
	}

	if finding.Severity != scanner.SeverityHigh {
		t.Errorf("severity = %d, want %d (HIGH)", finding.Severity, scanner.SeverityHigh)
	}

	if finding.Score != 9.3 {
		t.Errorf("score = %f, want 9.3 (CVSS 4.0)", finding.Score)
	}

	reachable, ok := finding.Display["reachable"]
	if !ok {
		t.Error("expected 'reachable' in Display for OSV call analysis")
	}
	if reachable != true {
		t.Error("expected reachable to be true")
	}
}

func TestParse_InvalidJSON(t *testing.T) {
	p := osvscanner.NewParser()
	_, err := p.Parse(context.Background(), strings.NewReader(`not json`))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}
