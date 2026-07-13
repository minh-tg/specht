package osvscanner_test

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xMinhx/specht/internal/parser/osvscanner"
	"github.com/xMinhx/specht/internal/scanner"
)

func TestName(t *testing.T) {
	s := osvscanner.NewScanner()
	assert.Equal(t, "osv-scanner", s.Name())
}

func TestDetect_ValidInput(t *testing.T) {
	s := osvscanner.NewScanner()
	data, err := os.ReadFile("testdata/go-scan.json")
	require.NoError(t, err)
	assert.True(t, s.DetectFormat(data))
}

func TestDetect_InvalidInput(t *testing.T) {
	s := osvscanner.NewScanner()
	assert.False(t, s.DetectFormat([]byte(`{}`)))
	assert.False(t, s.DetectFormat([]byte(`not json`)))
}

func TestParse_GoScan(t *testing.T) {
	s := osvscanner.NewScanner()
	data, err := os.ReadFile("testdata/go-scan.json")
	require.NoError(t, err)

	report, err := s.Parse(context.Background(), data)
	require.NoError(t, err)

	assert.Equal(t, "osv-scanner", report.ToolName)
	require.NotNil(t, report.Target)
	assert.Len(t, report.Findings, 1)

	finding := report.Findings[0]

	expectedFP := "GHSA-c3h9-896r-86jm:pkg:golang/github.com/gogo/protobuf"
	assert.Equal(t, expectedFP, finding.Fingerprint)
	assert.Equal(t, "sca", finding.FindingKind)
	assert.Equal(t, scanner.SeverityHigh, finding.Severity)
	assert.Equal(t, 9.3, finding.Score)

	// Aliases promoted from metadata to struct field
	require.Len(t, finding.Aliases, 1)
	assert.Equal(t, "CVE-2021-3121", finding.Aliases[0])

	// Reachability promoted from display to struct field
	require.NotNil(t, finding.Reachability)
	assert.True(t, *finding.Reachability)

	// CVSS extracted from severity array
	require.NotNil(t, finding.CVSS)
	assert.Equal(t, "4.0", finding.CVSS.Version)
	assert.Equal(t, 9.3, finding.CVSS.Score)
	assert.Contains(t, finding.CVSS.Vector, "CVSS:4.0")

	// Fix populated from fix version
	require.NotNil(t, finding.Fix)
	assert.Equal(t, "1.3.2", finding.Fix.Summary)

	// Legacy display/meta still populated for backward compat
	reachable, ok := finding.Display["reachable"]
	assert.True(t, ok)
	assert.Equal(t, true, reachable)
	assert.Equal(t, []string{"CVE-2021-3121"}, finding.Metadata["aliases"])
}

func TestParseCVSSInfo(t *testing.T) {
	s := osvscanner.NewScanner()
	data, err := os.ReadFile("testdata/go-scan.json")
	require.NoError(t, err)

	report, err := s.Parse(context.Background(), data)
	require.NoError(t, err)
	require.Len(t, report.Findings, 1)

	finding := report.Findings[0]
	require.NotNil(t, finding.CVSS)
	assert.Equal(t, "4.0", finding.CVSS.Version)
	assert.True(t, finding.CVSS.Score > 0)
}

func TestParse_InvalidJSON(t *testing.T) {
	s := osvscanner.NewScanner()
	_, err := s.Parse(context.Background(), []byte(`not json`))
	assert.Error(t, err)
}

func TestFindingKind(t *testing.T) {
	s := osvscanner.NewScanner()
	assert.Equal(t, "sca", s.FindingKind())
}
