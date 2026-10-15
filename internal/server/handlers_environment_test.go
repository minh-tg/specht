package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/port"
	"github.com/minh-tg/specht/internal/usecase"
)

const environmentRoute = "/api/v1/projects/my-app/environments/00000000-0000-0000-0000-0000000000e1"

func putEnvironment(t *testing.T, mock *mockUsecases, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, environmentRoute, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	testRouter(mock).ServeHTTP(w, req)
	return w
}

func TestUpdateEnvironment_Handler_ReturnsTheStoredRow(t *testing.T) {
	var got usecase.UpdateEnvironmentInput
	mock := &mockUsecases{updateEnvironmentFn: func(ctx context.Context, in usecase.UpdateEnvironmentInput) (*usecase.EnvironmentResponse, error) {
		got = in
		return &usecase.EnvironmentResponse{ID: in.EnvironmentID, Tier: in.Tier, InternetFacing: in.InternetFacing, DataSensitivity: in.DataSensitivity}, nil
	}}

	w := putEnvironment(t, mock, `{"tier":"production","internet_facing":true,"data_sensitivity":"restricted"}`)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, usecase.UpdateEnvironmentInput{
		ProjectSlug:     "my-app",
		EnvironmentID:   "00000000-0000-0000-0000-0000000000e1",
		Tier:            "production",
		InternetFacing:  true,
		DataSensitivity: "restricted",
	}, got)
	assert.Contains(t, w.Body.String(), `"data_sensitivity":"restricted"`)
}

func TestUpdateEnvironment_Handler_RequiresEveryField(t *testing.T) {
	for name, body := range map[string]string{
		"not json":       `nope`,
		"no tier":        `{"internet_facing":true,"data_sensitivity":"public"}`,
		"no exposure":    `{"tier":"test","data_sensitivity":"public"}`,
		"no sensitivity": `{"tier":"test","internet_facing":false}`,
	} {
		t.Run(name, func(t *testing.T) {
			mock := &mockUsecases{} // any usecase call would fail the test
			w := putEnvironment(t, mock, body)
			assert.Equal(t, http.StatusBadRequest, w.Code)
		})
	}
}

func TestUpdateEnvironment_Handler_MapsErrors(t *testing.T) {
	for name, tc := range map[string]struct {
		err    error
		status int
		code   string
	}{
		"access denied":       {usecase.ErrProjectAccessDenied, http.StatusForbidden, "project_access_denied"},
		"bad value":           {usecase.ErrInvalidEnvironment, http.StatusBadRequest, "invalid_environment"},
		"unknown environment": {usecase.ErrEnvironmentNotFound, http.StatusNotFound, "environment_not_found"},
		"unknown project":     {port.ErrNotFound, http.StatusNotFound, "not_found"},
		"store failure":       {errors.New("pq: connection refused at 10.0.0.5"), http.StatusInternalServerError, "environment_update_failed"},
	} {
		t.Run(name, func(t *testing.T) {
			mock := &mockUsecases{updateEnvironmentFn: func(context.Context, usecase.UpdateEnvironmentInput) (*usecase.EnvironmentResponse, error) {
				return nil, tc.err
			}}
			w := putEnvironment(t, mock, `{"tier":"test","internet_facing":false,"data_sensitivity":"public"}`)
			assert.Equal(t, tc.status, w.Code)
			assert.Contains(t, w.Body.String(), tc.code)
			assert.NotContains(t, w.Body.String(), "10.0.0.5", "internals stay out of the response")
		})
	}
}
