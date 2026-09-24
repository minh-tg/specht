package repo

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/minh-tg/specht/internal/port"
	"github.com/stretchr/testify/assert"
)

func TestMappingErr_NoRowsToErrNotFound(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{"direct pgx.ErrNoRows", pgx.ErrNoRows},
		{"wrapped pgx.ErrNoRows", fmt.Errorf("lookup finding: %w", pgx.ErrNoRows)},
		{"double wrapped pgx.ErrNoRows", fmt.Errorf("outer: %w", fmt.Errorf("inner: %w", pgx.ErrNoRows))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mappingErr(tt.err)
			assert.ErrorIs(t, got, port.ErrNotFound, "mappingErr must translate no-rows to port.ErrNotFound")
			assert.NotErrorIs(t, got, pgx.ErrNoRows, "the sentinel must not leak past the adapter boundary")
		})
	}
}

func TestMappingErr_PreservesOtherErrors(t *testing.T) {
	err := errors.New("database unavailable")
	got := mappingErr(err)
	assert.ErrorIs(t, got, err, "non-no-rows errors pass through unchanged")
	assert.NotErrorIs(t, got, port.ErrNotFound)
}

func TestMappingErr_Nil(t *testing.T) {
	assert.Nil(t, mappingErr(nil))
}

func TestIsDuplicateSlug(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"unique violation", &pgconn.PgError{Code: "23505"}, true},
		{"wrapped unique violation", fmt.Errorf("create: %w", &pgconn.PgError{Code: "23505"}), true},
		{"foreign key violation", &pgconn.PgError{Code: "23503"}, false},
		{"non-pg error", errors.New("connection lost"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isDuplicateSlug(tt.err))
		})
	}
}
