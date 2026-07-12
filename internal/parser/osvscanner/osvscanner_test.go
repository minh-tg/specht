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

	reachable, ok := finding.Display["reachable"]
	assert.True(t, ok)
	assert.Equal(t, true, reachable)
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
