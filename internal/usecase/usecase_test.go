package usecase

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"math/big"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
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
			if got != tt.want {
				t.Errorf("severityStr(%d) = %q, want %q", tt.input, got, tt.want)
			}
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
			if got != tt.want {
				t.Errorf("severityRank(%d) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

func TestScoreToNumeric(t *testing.T) {
	t.Run("positive score", func(t *testing.T) {
		n := scoreToNumeric(7.5)
		if !n.Valid {
			t.Fatal("expected valid numeric")
		}
		if n.Int.Cmp(big.NewInt(75)) != 0 || n.Exp != -1 {
			t.Errorf("unexpected numeric: Int=%s Exp=%d", n.Int.String(), n.Exp)
		}
	})

	t.Run("zero score returns null", func(t *testing.T) {
		n := scoreToNumeric(0)
		if n.Valid {
			t.Error("expected invalid numeric for zero score")
		}
	})

	t.Run("negative score returns null", func(t *testing.T) {
		n := scoreToNumeric(-1)
		if n.Valid {
			t.Error("expected invalid numeric for negative score")
		}
	})
}

func TestTextPtr(t *testing.T) {
	t.Run("non-empty text", func(t *testing.T) {
		tt := textPtr("hello")
		if !tt.Valid || tt.String != "hello" {
			t.Errorf("unexpected text: Valid=%v String=%q", tt.Valid, tt.String)
		}
	})

	t.Run("empty text returns null", func(t *testing.T) {
		tt := textPtr("")
		if tt.Valid {
			t.Error("expected invalid text for empty string")
		}
	})
}

func TestUUIDToString(t *testing.T) {
	id := pgtype.UUID{Bytes: [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, Valid: true}
	got := uuidToString(id)
	expected := "00010203-0405-0607-0809-0a0b0c0d0e0f"
	if got != expected {
		t.Errorf("uuidToString = %q, want %q", got, expected)
	}
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
			if err == nil {
				t.Error("expected error for invalid input")
			}
		})
	}
}

func TestNow(t *testing.T) {
	n := now()
	if !n.Valid {
		t.Error("expected valid timestamp")
	}
	if n.Time.IsZero() {
		t.Error("expected non-zero time")
	}
}

func TestMustMarshal(t *testing.T) {
	data := mustMarshal(map[string]string{"key": "value"})
	if !bytes.Contains(data, []byte("key")) {
		t.Errorf("mustMarshal = %q, want containing 'key'", data)
	}
}


