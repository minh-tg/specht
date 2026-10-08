package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/usecase"
)

func postRegister(router http.Handler) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "/api/v1/auth/register",
		strings.NewReader(`{"email":"new@example.com","password":"password123"}`))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "192.0.2.80:1234"
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func TestRouter_RegistrationIsOpenByDefault(t *testing.T) {
	called := false
	router := NewRouter(RouterConfig{
		Usecases: &mockUsecases{
			registerFn: func(ctx context.Context, email, password string) (*usecase.AuthResponse, error) {
				called = true
				return &usecase.AuthResponse{Token: "t", UserID: "u1", Email: email}, nil
			},
		},
		JWTAuth: testJWTAuth,
	})

	w := postRegister(router)

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.True(t, called)
}

func TestRouter_RegistrationDisabledRefusesBeforeTheUsecase(t *testing.T) {
	router := NewRouter(RouterConfig{
		Usecases: &mockUsecases{
			registerFn: func(ctx context.Context, email, password string) (*usecase.AuthResponse, error) {
				t.Fatal("a disabled registration endpoint must not reach the usecase")
				return nil, nil
			},
		},
		JWTAuth:              testJWTAuth,
		RegistrationDisabled: true,
	})

	w := postRegister(router)

	require.Equal(t, http.StatusForbidden, w.Code)
	assert.Equal(t, "registration_disabled", errorCodeOf(t, w))
}

func TestRouter_RegistrationDisabledLeavesLoginAvailable(t *testing.T) {
	router := NewRouter(RouterConfig{
		Usecases: &mockUsecases{
			loginFn: func(ctx context.Context, email, password string) (*usecase.AuthResponse, error) {
				return &usecase.AuthResponse{Token: "t", UserID: "u1", Email: email}, nil
			},
		},
		JWTAuth:              testJWTAuth,
		RegistrationDisabled: true,
	})
	req := httptest.NewRequest("POST", "/api/v1/auth/login",
		strings.NewReader(`{"email":"a@example.com","password":"password123"}`))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "192.0.2.81:1234"
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}
