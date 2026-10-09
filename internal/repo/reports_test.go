package repo

import (
	"math"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/minh-tg/specht/internal/db/sqlc"
)

func TestInt32CountRejectsOverflow(t *testing.T) {
	for _, count := range []int{math.MinInt32 - 1, math.MaxInt32 + 1} {
		t.Run("overflow", func(t *testing.T) {
			_, err := int32Count(count)
			if err == nil {
				t.Fatalf("int32Count(%d) returned nil error", count)
			}
			if !strings.Contains(err.Error(), "overflows int32") {
				t.Fatalf("int32Count(%d) error = %q, want int32 overflow", count, err)
			}
		})
	}
}

func TestInt32CountAcceptsBounds(t *testing.T) {
	for _, want := range []int32{math.MinInt32, math.MaxInt32} {
		got, err := int32Count(int(want))
		if err != nil {
			t.Fatalf("int32Count(%d) returned error: %v", want, err)
		}
		if got != want {
			t.Fatalf("int32Count(%d) = %d, want %d", want, got, want)
		}
	}
}

func TestReportRowToPort_MapsErrorMessage(t *testing.T) {
	failed := reportRowToPort(sqlc.Report{
		ErrorMessage: pgtype.Text{String: "Internal error: could not store findings.", Valid: true},
	})
	if failed.ErrorMessage == nil || *failed.ErrorMessage != "Internal error: could not store findings." {
		t.Fatalf("ErrorMessage = %v, want the stored reason", failed.ErrorMessage)
	}

	completed := reportRowToPort(sqlc.Report{})
	if completed.ErrorMessage != nil {
		t.Fatalf("ErrorMessage = %q for a report without a failure, want nil", *completed.ErrorMessage)
	}
}
