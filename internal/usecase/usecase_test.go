package usecase

import (
	"context"
	"encoding/json"
	"io"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vulnserve/vulnserve/internal/scanner"
)

func TestSeverityStr(t *testing.T) {
	tests := []struct {
		input scanner.Severity
		want  string
	}{
		{scanner.SeverityCritical, "critical"},
		{scanner.SeverityHigh, "high"},
		{scanner.SeverityMedium, "medium"},
		{scanner.SeverityLow, "low"},
		{scanner.SeverityUnknown, "unknown"},
		{scanner.Severity(99), "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := severityStr(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSeverityRank(t *testing.T) {
	tests := []struct {
		name  string
		input scanner.Severity
		want  int16
	}{
		{"critical", scanner.SeverityCritical, 4},
		{"high", scanner.SeverityHigh, 3},
		{"medium", scanner.SeverityMedium, 2},
		{"low", scanner.SeverityLow, 1},
		{"unknown", scanner.SeverityUnknown, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := severityRank(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestScoreToNumeric(t *testing.T) {
	t.Run("positive score", func(t *testing.T) {
		n := scoreToNumeric(7.5)
		require.True(t, n.Valid)
		assert.Equal(t, 0, n.Int.Cmp(big.NewInt(75)))
		assert.Equal(t, int32(-1), n.Exp)
	})

	t.Run("zero score returns null", func(t *testing.T) {
		n := scoreToNumeric(0)
		assert.False(t, n.Valid)
	})

	t.Run("negative score returns null", func(t *testing.T) {
		n := scoreToNumeric(-1)
		assert.False(t, n.Valid)
	})
}

func TestTextPtr(t *testing.T) {
	t.Run("non-empty text", func(t *testing.T) {
		tt := textPtr("hello")
		assert.True(t, tt.Valid)
		assert.Equal(t, "hello", tt.String)
	})

	t.Run("empty text returns null", func(t *testing.T) {
		tt := textPtr("")
		assert.False(t, tt.Valid)
	})
}

type mockParser struct {
	parseFn func(ctx context.Context, data []byte) (*scanner.NormalizedReport, error)
}

func (m *mockParser) Name() string                           { return "mock-parser" }
func (m *mockParser) ScanTypes() []scanner.ScanType          { return nil }

func (m *mockParser) Parse(ctx context.Context, r io.Reader) (*scanner.NormalizedReport, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return m.parseFn(ctx, data)
}

func TestIngestReport_ValidationErrors(t *testing.T) {
	uc := New(Deps{})

	tests := []struct {
		name  string
		input IngestReportInput
	}{
		{"empty project slug", IngestReportInput{ProjectSlug: "", Scanner: "trivy", RawData: json.RawMessage(`{}`)}},
		{"empty scanner name", IngestReportInput{ProjectSlug: "my-project", Scanner: "", RawData: json.RawMessage(`{}`)}},
		{"nil raw data", IngestReportInput{ProjectSlug: "my-project", Scanner: "trivy", RawData: nil}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := uc.IngestReport(context.Background(), tt.input)
			assert.Error(t, err)
		})
	}
}

func TestNow(t *testing.T) {
	n := now()
	assert.True(t, n.Valid)
	assert.False(t, n.Time.IsZero())
}

func TestMustMarshal(t *testing.T) {
	data := mustMarshal(map[string]string{"key": "value"})
	assert.Contains(t, string(data), "key")
}
