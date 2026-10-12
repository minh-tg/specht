package server

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/usecase"
)

func TestDeleteReport_Success(t *testing.T) {
	var gotSlug, gotID string
	mock := &mockUsecases{deleteReportFn: func(_ context.Context, slug, id string) (*usecase.ReportDeleteResponse, error) {
		gotSlug, gotID = slug, id
		return &usecase.ReportDeleteResponse{ArchivedFindings: 4}, nil
	}}

	w := inviteRequest(t, mock, "DELETE", "/api/v1/projects/payments/reports/r1", testToken(t), "")

	require.Equal(t, http.StatusNoContent, w.Code, w.Body.String())
	assert.Equal(t, "payments", gotSlug)
	assert.Equal(t, "r1", gotID)
	assert.Equal(t, "4", w.Header().Get("X-Archived-Findings"))
	assert.Empty(t, w.Body.String())
}

func TestDeleteReport_NeedsASession(t *testing.T) {
	w := inviteRequest(t, &mockUsecases{}, "DELETE", "/api/v1/projects/payments/reports/r1", "", "")
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestDeleteReport_ErrorMapping(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		status int
		code   string
	}{
		{"no access", usecase.ErrProjectAccessDenied, http.StatusForbidden, "project_access_denied"},
		{"bad id", usecase.ErrInvalidID, http.StatusBadRequest, "invalid_id"},
		{"unknown report", usecase.ErrReportNotFound, http.StatusNotFound, "not_found"},
		{"still processing", usecase.ErrReportProcessing, http.StatusConflict, "report_processing"},
		{"internal detail stays internal", errors.New("pq: deadlock at 10.0.0.7"), http.StatusInternalServerError, "internal_error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mock := &mockUsecases{deleteReportFn: func(context.Context, string, string) (*usecase.ReportDeleteResponse, error) {
				return nil, tc.err
			}}
			w := inviteRequest(t, mock, "DELETE", "/api/v1/projects/payments/reports/r1", testToken(t), "")
			assert.Equal(t, tc.status, w.Code)
			assert.Contains(t, w.Body.String(), tc.code)
			assert.NotContains(t, w.Body.String(), "10.0.0.7")
		})
	}
}
