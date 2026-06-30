package trivy_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vulnserve/vulnserve/internal/parser/trivy"
	"github.com/vulnserve/vulnserve/internal/scanner"
)

func TestName(t *testing.T) {
	p := trivy.NewParser()
	assert.Equal(t, "trivy", p.Name())
}

func TestScanTypes(t *testing.T) {
	p := trivy.NewParser()
	types := p.ScanTypes()
	require.NotEmpty(t, types)
}

func TestDetect_ValidInput(t *testing.T) {
	p := trivy.NewParser()
	data, err := os.ReadFile("testdata/alpine-scan.json")
	require.NoError(t, err)
	assert.True(t, p.Detect(data))
}

func TestDetect_InvalidInput(t *testing.T) {
	p := trivy.NewParser()
	assert.False(t, p.Detect([]byte(`{}`)))
	assert.False(t, p.Detect([]byte(`not json`)))
}

func TestParse_AlpineScan(t *testing.T) {
	p := trivy.NewParser()
	f, err := os.Open("testdata/alpine-scan.json")
	require.NoError(t, err)
	defer f.Close()

	report, err := p.Parse(context.Background(), f)
	require.NoError(t, err)

	assert.Equal(t, "trivy", report.ScannerName)
	require.NotNil(t, report.Target)
	assert.Equal(t, "alpine:3.20 (alpine 3.20.3)", report.Target.Identifier)
	require.Len(t, report.Findings, 2)

	tests := []struct {
		name         string
		fingerprint  string
		severity     scanner.Severity
		score        float64
		findingKind  string
		fixedVersion string
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
					assert.Equal(t, tt.severity, f.Severity)
					assert.Equal(t, tt.findingKind, f.FindingKind)
					assert.Equal(t, tt.score, f.Score)
					break
				}
			}
			assert.True(t, found, "finding with fingerprint %q not found", tt.fingerprint)
		})
	}
}

func TestParse_EmptyScan(t *testing.T) {
	p := trivy.NewParser()
	f, err := os.Open("testdata/empty-scan.json")
	require.NoError(t, err)
	defer f.Close()

	report, err := p.Parse(context.Background(), f)
	require.NoError(t, err)

	assert.Empty(t, report.Findings)
}

func TestParse_MultiTypeScan(t *testing.T) {
	p := trivy.NewParser()
	f, err := os.Open("testdata/multi-type-scan.json")
	require.NoError(t, err)
	defer f.Close()

	report, err := p.Parse(context.Background(), f)
	require.NoError(t, err)

	require.Len(t, report.Findings, 4)

	kinds := make(map[string]int)
	for _, f := range report.Findings {
		kinds[f.FindingKind]++
	}

	assert.Equal(t, 2, kinds["sca"])
	assert.Equal(t, 1, kinds["iac"])
	assert.Equal(t, 1, kinds["secret"])
}

func TestParse_InvalidJSON(t *testing.T) {
	p := trivy.NewParser()
	_, err := p.Parse(context.Background(), strings.NewReader(`not json`))
	assert.Error(t, err)
}
