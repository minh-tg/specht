package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/minh-tg/specht/internal/port"
	"github.com/minh-tg/specht/internal/usecase"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func postWaiver(t *testing.T, mock *mockUsecases, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", "/api/v1/projects/my-app/waivers"+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	authRouter(NewHandler(mock)).ServeHTTP(w, req)
	return w
}

func errorCode(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	return body.Error.Code
}

func TestRequestWaiver_Success(t *testing.T) {
	expires := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	mock := &mockUsecases{
		requestWaiverFn: func(_ context.Context, in usecase.RequestWaiverInput) (*usecase.WaiverResponse, error) {
			assert.Equal(t, "my-app", in.ProjectSlug)
			assert.Equal(t, []string{"f1", "f2"}, in.TargetIDs)
			assert.Equal(t, "not reachable", in.Reason)
			require.NotNil(t, in.ExpiresAt)
			assert.True(t, in.ExpiresAt.Equal(expires))
			r := sampleWaiverResponse()
			r.Status = usecase.WaiverStatusPending
			return &r, nil
		},
	}

	w := postWaiver(t, mock, "/requests", `{"target_ids":["f1","f2"],"reason":"not reachable","expires_at":"2030-01-02T03:04:05Z"}`)

	require.Equal(t, http.StatusCreated, w.Code)
	var resp usecase.WaiverResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, usecase.WaiverStatusPending, resp.Status)
}

func TestRequestWaiver_BadExpiry(t *testing.T) {
	w := postWaiver(t, &mockUsecases{}, "/requests", `{"target_ids":["f1"],"reason":"x","expires_at":"tomorrow"}`)
	require.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, "invalid_expires_at", errorCode(t, w))
}

func TestWaiverLifecycleErrorMapping(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		status int
		code   string
	}{
		{"validation", usecase.ErrInvalidWaiverRequest, http.StatusBadRequest, "invalid_body"},
		{"scope required", usecase.ErrWaiverScopeRequired, http.StatusBadRequest, "waiver_scope_required"},
		{"not pending", usecase.ErrWaiverNotPending, http.StatusConflict, "waiver_not_pending"},
		{"expired", usecase.ErrWaiverExpired, http.StatusConflict, "waiver_expired"},
		{"duplicate", usecase.ErrWaiverRequestExists, http.StatusConflict, "waiver_request_exists"},
		{"self approval", usecase.ErrWaiverSelfApproval, http.StatusForbidden, "self_approval"},
		{"missing", port.ErrNotFound, http.StatusNotFound, "not_found"},
		{"denied", usecase.ErrProjectAccessDenied, http.StatusForbidden, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mock := &mockUsecases{
				approveWaiverFn: func(context.Context, string, string, string) (*usecase.WaiverResponse, error) { return nil, tc.err },
			}
			w := postWaiver(t, mock, "/wvr-1/approve", `{}`)
			assert.Equal(t, tc.status, w.Code)
			if tc.code != "" {
				assert.Equal(t, tc.code, errorCode(t, w))
			}
		})
	}
}

func TestWaiverLifecycleUnknownErrorIsInternal(t *testing.T) {
	mock := &mockUsecases{
		rejectWaiverFn: func(context.Context, string, string, string) (*usecase.WaiverResponse, error) {
			return nil, errors.New("pq: connection refused at 10.0.0.5")
		},
	}
	w := postWaiver(t, mock, "/wvr-1/reject", `{"note":"no"}`)
	require.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NotContains(t, w.Body.String(), "10.0.0.5", "store detail must not leak")
}

func TestApproveRejectWithdrawPassArguments(t *testing.T) {
	approved := sampleWaiverResponse()
	approved.Status = usecase.WaiverStatusApproved
	mock := &mockUsecases{
		approveWaiverFn: func(_ context.Context, slug, id, note string) (*usecase.WaiverResponse, error) {
			assert.Equal(t, []string{"my-app", "wvr-1", "looks fine"}, []string{slug, id, note})
			return &approved, nil
		},
		rejectWaiverFn: func(_ context.Context, slug, id, note string) (*usecase.WaiverResponse, error) {
			assert.Equal(t, []string{"my-app", "wvr-1", "fix it"}, []string{slug, id, note})
			return &approved, nil
		},
		withdrawWaiverFn: func(_ context.Context, slug, id string) (*usecase.WaiverResponse, error) {
			assert.Equal(t, []string{"my-app", "wvr-1"}, []string{slug, id})
			return &approved, nil
		},
	}

	assert.Equal(t, http.StatusOK, postWaiver(t, mock, "/wvr-1/approve", `{"note":"looks fine"}`).Code)
	assert.Equal(t, http.StatusOK, postWaiver(t, mock, "/wvr-1/reject", `{"note":"fix it"}`).Code)
	assert.Equal(t, http.StatusOK, postWaiver(t, mock, "/wvr-1/withdraw", ``).Code, "withdraw needs no body")
}

func TestCreateWaiverScope(t *testing.T) {
	var got usecase.CreateWaiverInput
	mock := &mockUsecases{
		createWaiverFn: func(_ context.Context, in usecase.CreateWaiverInput) (*usecase.WaiverResponse, error) {
			got = in
			r := sampleWaiverResponse()
			return &r, nil
		},
	}

	require.Equal(t, http.StatusCreated, postWaiver(t, mock, "", `{"name":"everything","scope":"all"}`).Code)
	assert.True(t, got.ScopeAll)

	require.Equal(t, http.StatusCreated, postWaiver(t, mock, "", `{"name":"one","target_ids":["f1"]}`).Code)
	assert.False(t, got.ScopeAll)

	w := postWaiver(t, mock, "", `{"name":"x","scope":"everything"}`)
	require.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, "invalid_scope", errorCode(t, w))

	mock.createWaiverFn = func(context.Context, usecase.CreateWaiverInput) (*usecase.WaiverResponse, error) {
		return nil, usecase.ErrWaiverScopeRequired
	}
	w = postWaiver(t, mock, "", `{"name":"empty"}`)
	require.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, "waiver_scope_required", errorCode(t, w))
}

func TestListWaiversStatusFilter(t *testing.T) {
	mock := &mockUsecases{
		listWaiversFn: func(context.Context, string) ([]usecase.WaiverResponse, error) {
			return []usecase.WaiverResponse{}, nil
		},
	}
	get := func(query string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "/api/v1/projects/my-app/waivers/"+query, nil)
		w := httptest.NewRecorder()
		authRouter(NewHandler(mock)).ServeHTTP(w, req)
		return w
	}

	require.Equal(t, http.StatusOK, get("?status=pending,rejected").Code)
	assert.Equal(t, []string{"pending", "rejected"}, mock.waiverStatuses)

	w := get("?status=pending,bogus")
	require.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, "invalid_status", errorCode(t, w))
}
