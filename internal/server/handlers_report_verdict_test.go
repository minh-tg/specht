package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/minh-tg/specht/internal/usecase"
	"github.com/stretchr/testify/assert"
)

func TestReportVerdictsReturnConflictForIncompleteEvidence(t *testing.T) {
	mock := &mockUsecases{
		getIntroducedGateFn: func(context.Context, string, int16, string) (*usecase.GateStatusOutput, error) {
			return nil, usecase.ErrReportNotCompleted
		},
		previewPRCheckFn: func(context.Context, usecase.PRCheckPreviewInput) (*usecase.PRCheckPreview, error) {
			return nil, usecase.ErrReportNotCompleted
		},
	}
	for _, path := range []string{
		"/api/v1/projects/my-app/gate?introduced_only=true&report_id=report",
		"/api/v1/projects/my-app/pr-check?commit=abc123&report_id=report",
	} {
		t.Run(path, func(t *testing.T) {
			w := httptest.NewRecorder()
			testRouter(mock).ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
			assert.Equal(t, http.StatusConflict, w.Code)
			assert.Contains(t, w.Body.String(), "report_not_completed")
		})
	}
}
