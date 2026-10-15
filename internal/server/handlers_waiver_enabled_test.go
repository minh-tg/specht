package server

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/minh-tg/specht/internal/audit"
	"github.com/minh-tg/specht/internal/port"
	"github.com/minh-tg/specht/internal/usecase"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// seenVersion carries microseconds, which is what the waiver response now
// hands out and what the precondition has to round-trip.
const seenVersion = "2026-10-15T09:12:44.123456Z"

func TestRevokeAndRestoreWaiverPassArguments(t *testing.T) {
	want := time.Date(2026, 10, 15, 9, 12, 44, 123456000, time.UTC)
	for _, tc := range []struct {
		name string
		path string
		mock func(*testing.T, *[]*time.Time) *mockUsecases
	}{
		{"revoke", "/wvr-1/revoke", func(t *testing.T, got *[]*time.Time) *mockUsecases {
			return &mockUsecases{revokeWaiverFn: func(_ context.Context, slug, id, actor string, expected *time.Time) (*usecase.WaiverResponse, error) {
				assert.Equal(t, []string{"my-app", "wvr-1", "test-user"}, []string{slug, id, actor})
				*got = append(*got, expected)
				r := sampleWaiverResponse()
				r.Enabled = false
				return &r, nil
			}}
		}},
		{"restore", "/wvr-1/restore", func(t *testing.T, got *[]*time.Time) *mockUsecases {
			return &mockUsecases{restoreWaiverFn: func(_ context.Context, slug, id, actor string, expected *time.Time) (*usecase.WaiverResponse, error) {
				assert.Equal(t, []string{"my-app", "wvr-1", "test-user"}, []string{slug, id, actor})
				*got = append(*got, expected)
				return new(sampleWaiverResponse()), nil
			}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got []*time.Time
			mock := tc.mock(t, &got)

			w := postWaiver(t, mock, tc.path, `{"expected_updated_at":"`+seenVersion+`"}`)
			require.Equal(t, http.StatusOK, w.Code)
			w = postWaiver(t, mock, tc.path, ``)
			require.Equal(t, http.StatusOK, w.Code, "the body is optional")

			require.Len(t, got, 2)
			require.NotNil(t, got[0])
			assert.True(t, got[0].Equal(want), "the precondition keeps its microseconds, got %s", got[0])
			assert.Nil(t, got[1], "no body means no precondition")
		})
	}
}

func TestRevokeWaiverRejectsABadPrecondition(t *testing.T) {
	for _, path := range []string{"/wvr-1/revoke", "/wvr-1/restore"} {
		w := postWaiver(t, &mockUsecases{}, path, `{"expected_updated_at":"yesterday"}`)
		require.Equal(t, http.StatusBadRequest, w.Code, path)
		assert.Equal(t, "invalid_expected_updated_at", errorCode(t, w))

		w = postWaiver(t, &mockUsecases{}, path, `{"expected_updated_at":`)
		require.Equal(t, http.StatusBadRequest, w.Code, path)
		assert.Equal(t, "invalid_body", errorCode(t, w))
	}
}

func TestRevokeAndRestoreErrorMapping(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		status int
		code   string
	}{
		{"changed", usecase.ErrWaiverChanged, http.StatusConflict, "waiver_changed"},
		{"expired", usecase.ErrWaiverLapsed, http.StatusConflict, "waiver_expired"},
		{"not approved", usecase.ErrWaiverNotApproved, http.StatusConflict, "waiver_not_approved"},
		{"wrapped", errors.Join(errors.New("restore waiver"), usecase.ErrWaiverChanged), http.StatusConflict, "waiver_changed"},
		{"missing", port.ErrNotFound, http.StatusNotFound, "not_found"},
		{"denied", usecase.ErrProjectAccessDenied, http.StatusForbidden, ""},
	} {
		for _, path := range []string{"/wvr-1/revoke", "/wvr-1/restore", "/wvr-1/toggle"} {
			t.Run(tc.name+path, func(t *testing.T) {
				fail := func() (*usecase.WaiverResponse, error) { return nil, tc.err }
				mock := &mockUsecases{
					revokeWaiverFn: func(context.Context, string, string, string, *time.Time) (*usecase.WaiverResponse, error) {
						return fail()
					},
					restoreWaiverFn: func(context.Context, string, string, string, *time.Time) (*usecase.WaiverResponse, error) {
						return fail()
					},
					toggleWaiverFn: func(context.Context, string, string, string) (*usecase.WaiverResponse, error) {
						return fail()
					},
				}
				w := postWaiver(t, mock, path, ``)
				assert.Equal(t, tc.status, w.Code)
				if tc.code != "" {
					assert.Equal(t, tc.code, errorCode(t, w))
				}
			})
		}
	}
}

func TestRevokeWaiverUnknownErrorDoesNotLeak(t *testing.T) {
	mock := &mockUsecases{
		revokeWaiverFn: func(context.Context, string, string, string, *time.Time) (*usecase.WaiverResponse, error) {
			return nil, errors.New("pq: connection refused at 10.0.0.5")
		},
	}
	w := postWaiver(t, mock, "/wvr-1/revoke", ``)
	require.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NotContains(t, w.Body.String(), "10.0.0.5")
	assert.Contains(t, w.Body.String(), "could not revoke waiver")
}

func TestRevokeAndRestoreWriteTheirOwnAuditEntries(t *testing.T) {
	var buf bytes.Buffer
	h := NewHandler(&mockUsecases{
		revokeWaiverFn: func(context.Context, string, string, string, *time.Time) (*usecase.WaiverResponse, error) {
			return new(sampleWaiverResponse()), nil
		},
		restoreWaiverFn: func(context.Context, string, string, string, *time.Time) (*usecase.WaiverResponse, error) {
			return new(sampleWaiverResponse()), nil
		},
	})
	h.audit = audit.NewLogger(slog.New(slog.NewTextHandler(&buf, nil)))
	router := authRouter(h)

	for _, action := range []string{"revoke", "restore"} {
		req := httptest.NewRequest("POST", "/api/v1/projects/my-app/waivers/wvr-1/"+action, strings.NewReader(``))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)
	}

	logged := buf.String()
	assert.Contains(t, logged, "audit=waiver.revoke")
	assert.Contains(t, logged, "audit=waiver.restore")
	assert.Contains(t, logged, "principal_id=test-user")
	assert.NotContains(t, logged, "audit=waiver.toggle")
}
