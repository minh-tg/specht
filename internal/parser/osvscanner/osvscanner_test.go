package osvscanner_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xMinhx/specht/internal/parser/osvscanner"
	"github.com/xMinhx/specht/internal/scanner"
)

func TestName(t *testing.T) {
	p := osvscanner.NewParser()
	assert.Equal(t, "osv-scanner", p.Name())
}

func TestScanTypes(t *testing.T) {
	p := osvscanner.NewParser()
	types := p.ScanTypes()
	require.NotEmpty(t, types)
}

func TestDetect_ValidInput(t *testing.T) {
	p := osvscanner.NewParser()
	data, err := os.ReadFile("testdata/go-scan.json")
	require.NoError(t, err)
	assert.True(t, p.Detect(data))
}

func TestDetect_InvalidInput(t *testing.T) {
	p := osvscanner.NewParser()
	assert.False(t, p.Detect([]byte(`{}`)))
	assert.False(t, p.Detect([]byte(`not json`)))
}

func TestParse_GoScan(t *testing.T) {
	p := osvscanner.NewParser()
	f, err := os.Open("testdata/go-scan.json")
	require.NoError(t, err)
	defer f.Close()

	report, err := p.Parse(context.Background(), f)
	require.NoError(t, err)

	assert.Equal(t, "osv-scanner", report.ScannerName)
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
	p := osvscanner.NewParser()
	_, err := p.Parse(context.Background(), strings.NewReader(`not json`))
	assert.Error(t, err)
}
