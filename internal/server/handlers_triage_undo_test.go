package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/usecase"
)

func undoRequest(body string) *http.Request {
	return authRequest("POST", "/api/v1/findings/abc-123/analysis/undo", body)
}

func TestUndoTriage_Success(t *testing.T) {
	var got usecase.UndoTriageInput
	mock := &mockUsecases{
		undoTriageFn: func(ctx context.Context, input usecase.UndoTriageInput) (*usecase.TriageOutput, error) {
			got = input
			return &usecase.TriageOutput{FindingID: "abc-123", AnalysisState: "accepted_risk", GateEffect: "ignore", EventID: "ev-2"}, nil
		},
	}
	w := httptest.NewRecorder()
	testRouter(mock).ServeHTTP(w, undoRequest(`{"event_id":"ev-1"}`))

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, usecase.UndoTriageInput{FindingID: "abc-123", EventID: "ev-1", UserID: "test-user"}, got)
	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "accepted_risk", resp["analysis_state"])
	assert.Equal(t, "ignore", resp["gate_effect"])
	assert.Equal(t, "ev-2", resp["event_id"])
}

func TestUndoTriage_Errors(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
	}{
		{"conflict", fmt.Errorf("wrapped: %w", usecase.ErrAnalysisConflict), http.StatusConflict, "analysis_conflict"},
		{"unavailable", usecase.ErrUndoUnavailable, http.StatusConflict, "undo_unavailable"},
		{"expiry passed", usecase.ErrPreviousExpiryPassed, http.StatusConflict, "previous_expiry_passed"},
		{"finding missing", usecase.ErrFindingNotFound, http.StatusNotFound, "not_found"},
		{"bad finding id", usecase.ErrInvalidFindingID, http.StatusBadRequest, "invalid_id"},
		{"bad event id", usecase.ErrInvalidEventID, http.StatusBadRequest, "invalid_event_id"},
		{"store failure", fmt.Errorf("pq: secret detail"), http.StatusInternalServerError, "undo_failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mock := &mockUsecases{
				undoTriageFn: func(context.Context, usecase.UndoTriageInput) (*usecase.TriageOutput, error) {
					return nil, tc.err
				},
			}
			w := httptest.NewRecorder()
			testRouter(mock).ServeHTTP(w, undoRequest(`{"event_id":"ev-1"}`))

			assert.Equal(t, tc.wantStatus, w.Code)
			var resp apiError
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
			assert.Equal(t, tc.wantCode, resp.Error.Code)
			assert.NotEmpty(t, resp.Error.Message)
			assert.NotContains(t, resp.Error.Message, "secret detail")
		})
	}
}

func TestUndoTriage_RejectsBadBodies(t *testing.T) {
	mock := &mockUsecases{}
	for name, body := range map[string]string{
		"missing event id": `{}`,
		"empty event id":   `{"event_id":""}`,
		"not json":         `nope`,
	} {
		t.Run(name, func(t *testing.T) {
			w := httptest.NewRecorder()
			testRouter(mock).ServeHTTP(w, undoRequest(body))
			assert.Equal(t, http.StatusBadRequest, w.Code)
		})
	}
}

func TestUndoTriage_NilOrEmptyIdentity(t *testing.T) {
	h := &Handler{}
	body := `{"event_id":"ev-1"}`

	req := httptest.NewRequest("POST", "/api/v1/findings/abc-123/analysis/undo", strings.NewReader(body))
	req = addChiURLParam(req, "id", "abc-123")
	w := httptest.NewRecorder()
	h.UndoTriage(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	ctx := auth.ContextWithIdentity(context.Background(), &auth.Identity{IsAPIKey: true, UserID: ""})
	req2 := httptest.NewRequest("POST", "/api/v1/findings/abc-123/analysis/undo", strings.NewReader(body)).WithContext(ctx)
	req2 = addChiURLParam(req2, "id", "abc-123")
	w2 := httptest.NewRecorder()
	h.UndoTriage(w2, req2)
	assert.Equal(t, http.StatusUnauthorized, w2.Code)
}
