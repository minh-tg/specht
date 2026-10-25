package server

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/minh-tg/specht/internal/usecase"
)

// A malformed waiver id is the caller's mistake. Every waiver id route used to
// answer 500 internal_error for it and log at error level.
func TestWaiverIDRoutes_MalformedIDIs400(t *testing.T) {
	bad := fmt.Errorf("invalid waiver id: %w", usecase.ErrInvalidID)
	mock := &mockUsecases{
		getWaiverFn: func(context.Context, string, string) (*usecase.WaiverDetailResponse, error) { return nil, bad },
		updateWaiverFn: func(context.Context, usecase.UpdateWaiverInput) (*usecase.WaiverResponse, error) {
			return nil, bad
		},
		deleteWaiverFn: func(context.Context, string, string) error { return bad },
		toggleWaiverFn: func(context.Context, string, string, string) (*usecase.WaiverResponse, error) { return nil, bad },
		revokeWaiverFn: func(context.Context, string, string, string, *time.Time) (*usecase.WaiverResponse, error) {
			return nil, bad
		},
		restoreWaiverFn: func(context.Context, string, string, string, *time.Time) (*usecase.WaiverResponse, error) {
			return nil, bad
		},
		approveWaiverFn: func(context.Context, string, string, string) (*usecase.WaiverResponse, error) { return nil, bad },
		rejectWaiverFn:  func(context.Context, string, string, string) (*usecase.WaiverResponse, error) { return nil, bad },
		withdrawWaiverFn: func(context.Context, string, string) (*usecase.WaiverResponse, error) {
			return nil, bad
		},
		listWaiverEventsFn: func(context.Context, string, string) ([]usecase.WaiverEventResp, error) { return nil, bad },
	}
	router := authRouter(NewHandler(mock))
	const base = "/api/v1/projects/my-app/waivers/abc"
	for _, tc := range []struct{ method, path, body string }{
		{"GET", base, ""},
		{"PUT", base, `{"name":"n"}`},
		{"DELETE", base, ""},
		{"POST", base + "/toggle", ""},
		{"POST", base + "/revoke", `{}`},
		{"POST", base + "/restore", `{}`},
		{"POST", base + "/approve", `{}`},
		{"POST", base + "/reject", `{"note":"no"}`},
		{"POST", base + "/withdraw", ""},
		{"GET", base + "/events", ""},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			requireAPIError(t, w, http.StatusBadRequest, "invalid_id")
		})
	}
}
