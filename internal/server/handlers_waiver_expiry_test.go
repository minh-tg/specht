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

// TestUpdateWaiver_ExpiresAtTriState pins the update contract: malformed
// timestamps never reach the usecase, the empty string clears the stored
// expiry, an RFC3339 value sets it, and omission leaves it untouched.
func TestUpdateWaiver_ExpiresAtTriState(t *testing.T) {
	var got *usecase.UpdateWaiverInput
	mock := &mockUsecases{
		updateWaiverFn: func(ctx context.Context, input usecase.UpdateWaiverInput) (*usecase.WaiverResponse, error) {
			got = &input
			r := sampleWaiverResponse()
			return &r, nil
		},
	}
	h := NewHandler(mock)
	router := authRouter(h)

	put := func(body string) (int, string) {
		got = nil
		req := httptest.NewRequest("PUT", "/api/v1/projects/my-app/waivers/w-1", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w.Code, w.Body.String()
	}

	// Malformed: 400 invalid_expires_at, usecase untouched.
	code, raw := put(`{"name":"x","expires_at":"soon"}`)
	require.Equal(t, http.StatusBadRequest, code)
	var errResp struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal([]byte(raw), &errResp))
	assert.Equal(t, "invalid_expires_at", errResp.Error.Code)
	assert.Nil(t, got, "usecase must not be called for a malformed expires_at")

	// Valid: forwarded to the usecase.
	code, _ = put(`{"name":"x","expires_at":"2030-06-30T12:00:00Z"}`)
	assert.Equal(t, http.StatusOK, code)
	require.NotNil(t, got)
	require.NotNil(t, got.ExpiresAt)
	assert.Equal(t, "2030-06-30T12:00:00Z", got.ExpiresAt.Format(time.RFC3339))
	assert.False(t, got.ClearExpiresAt)

	// Empty string: clears.
	code, _ = put(`{"name":"x","expires_at":""}`)
	assert.Equal(t, http.StatusOK, code)
	require.NotNil(t, got)
	assert.True(t, got.ClearExpiresAt)
	assert.Nil(t, got.ExpiresAt)

	// Omitted: untouched.
	code, _ = put(`{"name":"x"}`)
	assert.Equal(t, http.StatusOK, code)
	require.NotNil(t, got)
	assert.False(t, got.ClearExpiresAt)
	assert.Nil(t, got.ExpiresAt)
}
