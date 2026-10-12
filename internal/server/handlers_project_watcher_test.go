package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/usecase"
)

func ptr[T any](v T) *T { return &v }

func recordOf(w *httptest.ResponseRecorder) *struct {
	code int
	body string
} {
	return &struct {
		code int
		body string
	}{w.Code, w.Body.String()}
}

func TestGetProjectWatcher_ReturnsTheSettings(t *testing.T) {
	mock := &mockUsecases{getProjectWatcherFn: func(_ context.Context, slug string) (*usecase.ProjectWatcherResponse, error) {
		return &usecase.ProjectWatcherResponse{
			Enabled: true, IntervalSeconds: 3600, EffectiveEnabled: true, EffectiveIntervalSeconds: 3600,
			Status: usecase.WatcherStatusOK, Healthy: true,
		}, nil
	}}

	w := inviteRequest(t, mock, "GET", "/api/v1/projects/payments/watcher", testToken(t), "")

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), `"status":"ok"`)
	assert.Contains(t, w.Body.String(), `"effective_interval_seconds":3600`)
}

func TestGetProjectWatcher_NeedsAuthentication(t *testing.T) {
	w := inviteRequest(t, &mockUsecases{}, "GET", "/api/v1/projects/payments/watcher", "", "")
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUpdateProjectWatcher_ParsesTheBody(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want usecase.WatcherSettingsInput
	}{
		{"switch only", `{"enabled":false}`, usecase.WatcherSettingsInput{Enabled: ptr(false)}},
		{"interval only", `{"interval_seconds":7200}`, usecase.WatcherSettingsInput{IntervalSeconds: ptr(int32(7200))}},
		{"both", `{"enabled":true,"interval_seconds":3600}`, usecase.WatcherSettingsInput{Enabled: ptr(true), IntervalSeconds: ptr(int32(3600))}},
		{"null returns the interval to its default", `{"interval_seconds":null}`, usecase.WatcherSettingsInput{ResetInterval: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got usecase.WatcherSettingsInput
			mock := &mockUsecases{updateProjectWatcherFn: func(_ context.Context, slug string, in usecase.WatcherSettingsInput) (*usecase.ProjectWatcherResponse, error) {
				assert.Equal(t, "payments", slug)
				got = in
				return &usecase.ProjectWatcherResponse{Status: usecase.WatcherStatusOK, Healthy: true}, nil
			}}

			w := inviteRequest(t, mock, "PUT", "/api/v1/projects/payments/watcher", testToken(t), tc.body)

			require.Equal(t, http.StatusOK, w.Code, w.Body.String())
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestUpdateProjectWatcher_RejectsMalformedBodies(t *testing.T) {
	mock := &mockUsecases{updateProjectWatcherFn: func(context.Context, string, usecase.WatcherSettingsInput) (*usecase.ProjectWatcherResponse, error) {
		t.Fatal("a malformed body must not reach the use case")
		return nil, nil
	}}
	for name, body := range map[string]string{
		"enabled as text":     `{"enabled":"yes"}`,
		"interval as text":    `{"interval_seconds":"hourly"}`,
		"fractional interval": `{"interval_seconds":1.5}`,
		"negative interval":   `{"interval_seconds":-1}`,
		"huge interval":       `{"interval_seconds":99999999999}`,
		"unknown field":       `{"interval":3600}`,
		"not an object":       `[1]`,
	} {
		t.Run(name, func(t *testing.T) {
			w := inviteRequest(t, mock, "PUT", "/api/v1/projects/payments/watcher", testToken(t), body)
			assert.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
		})
	}
}

func TestProjectWatcherErrorMapping(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		status int
		code   string
	}{
		{"no access", usecase.ErrProjectAccessDenied, http.StatusForbidden, "project_access_denied"},
		{"out of range", usecase.ErrInvalidWatcherSettings, http.StatusBadRequest, "invalid_watcher_settings"},
		{"internal detail stays internal", errors.New("pq: out of memory at 10.0.0.3"), http.StatusInternalServerError, "internal_error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mock := &mockUsecases{
				getProjectWatcherFn: func(context.Context, string) (*usecase.ProjectWatcherResponse, error) { return nil, tc.err },
				updateProjectWatcherFn: func(context.Context, string, usecase.WatcherSettingsInput) (*usecase.ProjectWatcherResponse, error) {
					return nil, tc.err
				},
			}
			for _, w := range []*struct {
				code int
				body string
			}{
				recordOf(inviteRequest(t, mock, "GET", "/api/v1/projects/payments/watcher", testToken(t), "")),
				recordOf(inviteRequest(t, mock, "PUT", "/api/v1/projects/payments/watcher", testToken(t), `{"enabled":true}`)),
			} {
				assert.Equal(t, tc.status, w.code)
				assert.Contains(t, w.body, tc.code)
				assert.NotContains(t, w.body, "10.0.0.3")
			}
		})
	}
}
