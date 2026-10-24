package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/usecase"
)

func TestTriageExpiredInputReturnsValidationError(t *testing.T) {
	mock := &mockUsecases{
		triageFindingFn: func(context.Context, usecase.TriageInput) (*usecase.TriageOutput, error) {
			return nil, usecase.ErrExpiryPassed
		},
		bulkTriageFn: func(context.Context, usecase.BulkTriageInput) ([]usecase.TriageOutput, error) {
			return nil, usecase.ErrExpiryPassed
		},
	}
	for _, tc := range []struct{ method, path, body string }{
		{"PATCH", "/api/v1/findings/00000000-0000-0000-0000-000000000021", `{"analysis_state":"accepted_risk","reason":"test","analysis_expires_at":"2000-01-01T00:00:00Z"}`},
		{"POST", "/api/v1/findings/bulk-analysis", `{"finding_ids":["00000000-0000-0000-0000-000000000021"],"analysis_state":"accepted_risk","reason":"test","analysis_expires_at":"2000-01-01T00:00:00Z"}`},
	} {
		t.Run(tc.method, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			testRouter(mock).ServeHTTP(w, req)
			require.Equal(t, http.StatusUnprocessableEntity, w.Code, w.Body.String())
			require.Contains(t, w.Body.String(), `"expiry_passed"`)
		})
	}
}
