package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/minh-tg/specht/internal/usecase"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCreateWaiver_InvalidExpiresAtRejectsMalformedTimestamp: the sweeper
// and gate trust expires_at, so a non-RFC3339 value must be rejected at the
// API edge rather than silently stored as garbage or dropped.
func TestCreateWaiver_InvalidExpiresAtRejectsMalformedTimestamp(t *testing.T) {
	mock := &mockUsecases{
		createWaiverFn: func(ctx context.Context, input usecase.CreateWaiverInput) (*usecase.WaiverResponse, error) {
			t.Fatal("usecase must not be called for a malformed expires_at")
			return nil, nil
		},
	}
	h := NewHandler(mock)
	router := authRouter(h)
	body := strings.NewReader(`{"name":"bad-window","expires_at":"next tuesday"}`)
	req := httptest.NewRequest("POST", "/api/v1/projects/my-app/waivers", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var errResp struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &errResp))
	assert.Equal(t, "invalid_expires_at", errResp.Error.Code)
}

// TestCreateWaiver_ForwardsExpiresAt pins the valid edge: RFC3339 input
// reaches the usecase, malformed input never does.
func TestCreateWaiver_ForwardsExpiresAt(t *testing.T) {
	expiresAt := "2030-06-30T12:00:00Z"
	mock := &mockUsecases{
		createWaiverFn: func(ctx context.Context, input usecase.CreateWaiverInput) (*usecase.WaiverResponse, error) {
			require.NotNil(t, input.ExpiresAt)
			assert.Equal(t, expiresAt, input.ExpiresAt.Format(time.RFC3339))
			r := sampleWaiverResponse()
			r.ExpiresAt = &expiresAt
			return &r, nil
		},
	}
	h := NewHandler(mock)
	router := authRouter(h)
	body := strings.NewReader(`{"name":"release-window","expires_at":"` + expiresAt + `"}`)
	req := httptest.NewRequest("POST", "/api/v1/projects/my-app/waivers", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	var resp usecase.WaiverResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.NotNil(t, resp.ExpiresAt)
	assert.Equal(t, expiresAt, *resp.ExpiresAt)
}
