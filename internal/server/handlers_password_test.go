package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/usecase"
)

func putPassword(t *testing.T, mock *mockUsecases, body string, withIdentity bool) *httptest.ResponseRecorder {
	t.Helper()
	router := testRouter(mock)
	req := httptest.NewRequest("PUT", "/api/v1/me/password", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if withIdentity {
		req = req.WithContext(auth.ContextWithIdentity(req.Context(), &auth.Identity{UserID: "test-user"}))
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func errorBody(t *testing.T, w *httptest.ResponseRecorder) (code, message string) {
	t.Helper()
	var resp struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	return resp.Error.Code, resp.Error.Message
}

func TestChangePassword_Success(t *testing.T) {
	mock := &mockUsecases{
		changePasswordFn: func(ctx context.Context, userID, current, next string) (*usecase.AuthResponse, error) {
			assert.Equal(t, "test-user", userID)
			assert.Equal(t, "old-password", current)
			assert.Equal(t, "new-password", next)
			return &usecase.AuthResponse{Token: "fresh-token", RefreshToken: "fresh-refresh", UserID: userID, Email: "a@b.co"}, nil
		},
	}

	w := putPassword(t, mock, `{"current_password":"old-password","new_password":"new-password"}`, true)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp usecase.AuthResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "fresh-token", resp.Token)
	assert.Equal(t, "fresh-refresh", resp.RefreshToken)
	assert.NotContains(t, w.Body.String(), "password", "the response carries tokens, never a password or hash")
}

func TestChangePassword_WrongCurrentPasswordIsABadRequestNotASignOut(t *testing.T) {
	mock := &mockUsecases{
		changePasswordFn: func(ctx context.Context, userID, current, next string) (*usecase.AuthResponse, error) {
			return nil, usecase.ErrWrongPassword
		},
	}

	w := putPassword(t, mock, `{"current_password":"nope","new_password":"new-password"}`, true)

	assert.Equal(t, http.StatusBadRequest, w.Code,
		"a 401 here would make the client think the session expired and sign the person out")
	code, _ := errorBody(t, w)
	assert.Equal(t, "wrong_password", code)
}

func TestChangePassword_RuleViolationShowsWhatToFix(t *testing.T) {
	mock := &mockUsecases{
		changePasswordFn: func(ctx context.Context, userID, current, next string) (*usecase.AuthResponse, error) {
			return nil, usecase.NewCredentialInputError("password must be at least 8 characters")
		},
	}

	w := putPassword(t, mock, `{"current_password":"old-password","new_password":"short"}`, true)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	code, message := errorBody(t, w)
	assert.Equal(t, "invalid_password", code)
	assert.Equal(t, "password must be at least 8 characters", message)
}

func TestChangePassword_SSOOnlyAccountGetsAConflict(t *testing.T) {
	mock := &mockUsecases{
		changePasswordFn: func(ctx context.Context, userID, current, next string) (*usecase.AuthResponse, error) {
			return nil, usecase.ErrNoLocalPassword
		},
	}

	w := putPassword(t, mock, `{"current_password":"x","new_password":"new-password"}`, true)

	assert.Equal(t, http.StatusConflict, w.Code)
	code, _ := errorBody(t, w)
	assert.Equal(t, "no_local_password", code)
}

func TestChangePassword_AnAccountChangeAfterTheWriteAsksForANewSignIn(t *testing.T) {
	mock := &mockUsecases{
		changePasswordFn: func(ctx context.Context, userID, current, next string) (*usecase.AuthResponse, error) {
			return nil, usecase.ErrAccountChanged
		},
	}

	w := putPassword(t, mock, `{"current_password":"old-password","new_password":"new-password"}`, true)

	assert.Equal(t, http.StatusConflict, w.Code)
	code, _ := errorBody(t, w)
	assert.Equal(t, "account_changed", code)
}

func TestChangePassword_InternalErrorsStayGeneric(t *testing.T) {
	mock := &mockUsecases{
		changePasswordFn: func(ctx context.Context, userID, current, next string) (*usecase.AuthResponse, error) {
			return nil, errors.New("pq: connection refused to 10.0.0.5")
		},
	}

	w := putPassword(t, mock, `{"current_password":"old-password","new_password":"new-password"}`, true)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NotContains(t, w.Body.String(), "10.0.0.5")
}

func TestChangePassword_NeedsASession(t *testing.T) {
	// The real router, not testRouter: this proves the production route sits
	// behind authentication.
	router := NewRouter(RouterConfig{Usecases: &mockUsecases{}, JWTAuth: testJWTAuth})
	req := httptest.NewRequest("PUT", "/api/v1/me/password",
		strings.NewReader(`{"current_password":"old-password","new_password":"new-password"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestChangePassword_AnAPIKeyCannotChangeAPassword(t *testing.T) {
	// Called directly: testRouter replaces the identity on every request.
	h := &Handler{usecase: &mockUsecases{}}
	req := httptest.NewRequest("PUT", "/api/v1/me/password",
		strings.NewReader(`{"current_password":"old-password","new_password":"new-password"}`))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(auth.ContextWithIdentity(req.Context(), &auth.Identity{UserID: "key-1", IsAPIKey: true}))
	w := httptest.NewRecorder()
	h.ChangePassword(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code, "the handler refuses keys even if a route guard is ever dropped")
}

func TestChangePassword_RejectsAMalformedBody(t *testing.T) {
	w := putPassword(t, &mockUsecases{}, `{not json`, true)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}
