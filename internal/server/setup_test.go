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

	"github.com/minh-tg/specht/internal/usecase"
)

func postSetup(t *testing.T, mock *mockUsecases, body string) *httptest.ResponseRecorder {
	t.Helper()
	router := NewRouter(RouterConfig{Usecases: mock, JWTAuth: testJWTAuth})
	req := httptest.NewRequest("POST", "/api/v1/setup", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "192.0.2.77:1234"
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func TestSetup_CreatesTheFirstAdmin(t *testing.T) {
	var got usecase.SetupInput
	mock := &mockUsecases{setupFn: func(_ context.Context, in usecase.SetupInput) (*usecase.AuthResponse, error) {
		got = in
		return &usecase.AuthResponse{Token: "t", RefreshToken: "r", UserID: "u1", Email: in.Email}, nil
	}}

	w := postSetup(t, mock, `{"token":"abc","email":"root@example.com","password":"correct-horse","display_name":"Root"}`)

	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	assert.Equal(t, usecase.SetupInput{Token: "abc", Email: "root@example.com", Password: "correct-horse", DisplayName: "Root"}, got)
	assert.Contains(t, w.Body.String(), `"token":"t"`)
}

func TestSetup_ErrorMapping(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		status int
		code   string
	}{
		{"closed answers as if the route were absent", usecase.ErrSetupClosed, http.StatusNotFound, "not_found"},
		{"wrong token", usecase.ErrInvalidSetupToken, http.StatusForbidden, "invalid_setup_token"},
		{"weak password", usecase.ErrInvalidCredentialInput, http.StatusBadRequest, "invalid_credentials"},
		{"anything else is internal", errors.New("pq: connection refused at 10.0.0.5"), http.StatusInternalServerError, "internal_error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mock := &mockUsecases{setupFn: func(context.Context, usecase.SetupInput) (*usecase.AuthResponse, error) { return nil, tc.err }}
			w := postSetup(t, mock, `{"token":"x","email":"a@b.co","password":"password1"}`)
			assert.Equal(t, tc.status, w.Code)
			assert.Contains(t, w.Body.String(), tc.code)
			assert.NotContains(t, w.Body.String(), "10.0.0.5")
		})
	}
}

func TestCapabilities_ReportsSetupAndStopsCachingWhileItIsNeeded(t *testing.T) {
	required := true
	mock := &mockUsecases{setupRequiredFn: func(context.Context) (bool, error) { return required, nil }}

	w, body := getCapabilitiesWith(t, RouterConfig{Usecases: mock})
	require.Equal(t, http.StatusOK, w.Code)
	assert.True(t, body.Setup.Required)
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"), "the answer flips the moment setup completes, so it is not cached")

	required = false
	w, body = getCapabilitiesWith(t, RouterConfig{Usecases: mock})
	assert.False(t, body.Setup.Required)
	assert.Equal(t, "public, max-age=60", w.Header().Get("Cache-Control"))
}

func TestCapabilities_FailedSetupCheckDoesNotInventASetupScreen(t *testing.T) {
	mock := &mockUsecases{setupRequiredFn: func(context.Context) (bool, error) { return false, errors.New("db down") }}
	_, body := getCapabilitiesWith(t, RouterConfig{Usecases: mock})
	assert.False(t, body.Setup.Required)
}
