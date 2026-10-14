package server

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/minh-tg/specht/internal/usecase"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const resetTargetID = "00000000-0000-0000-0000-0000000000a1"

func TestCreatePasswordResetLink_ReturnsTheLinkOnce(t *testing.T) {
	mock := &mockUsecases{}
	var gotID string
	mock.createPasswordResetLink = func(ctx context.Context, userID string) (*usecase.PasswordResetLinkResponse, error) {
		gotID = userID
		return &usecase.PasswordResetLinkResponse{Link: "/reset/tok", ExpiresAt: "2026-10-15T00:00:00Z"}, nil
	}
	w := postJSON(testRouter(mock), "/api/v1/users/"+resetTargetID+"/reset-link", `{}`)
	require.Equal(t, http.StatusCreated, w.Code)
	assert.Equal(t, resetTargetID, gotID)
	assert.JSONEq(t, `{"link":"/reset/tok","expires_at":"2026-10-15T00:00:00Z"}`, w.Body.String())
}

func TestCreatePasswordResetLink_ErrorMapping(t *testing.T) {
	for name, tc := range map[string]struct {
		err    error
		status int
		code   string
	}{
		"not an admin":    {usecase.ErrProjectAccessDenied, http.StatusForbidden, "insufficient_role"},
		"bad id":          {usecase.ErrInvalidID, http.StatusBadRequest, "invalid_id"},
		"no such account": {usecase.ErrAccountNotFound, http.StatusNotFound, "not_found"},
		"system account":  {usecase.ErrSystemAccount, http.StatusConflict, "system_account"},
		"sso only":        {usecase.ErrNoLocalPassword, http.StatusConflict, "no_local_password"},
		"deactivated":     {usecase.ErrAccountDeactivated, http.StatusConflict, "account_deactivated"},
		"unexpected":      {errors.New("connection reset"), http.StatusInternalServerError, "internal_error"},
	} {
		mock := &mockUsecases{createPasswordResetLink: func(context.Context, string) (*usecase.PasswordResetLinkResponse, error) {
			return nil, tc.err
		}}
		w := postJSON(testRouter(mock), "/api/v1/users/"+resetTargetID+"/reset-link", `{}`)
		assert.Equal(t, tc.status, w.Code, name)
		assert.Equal(t, tc.code, errorCodeOf(t, w), name)
	}
}

func TestResetPassword_SetsThePasswordFromTheLink(t *testing.T) {
	mock := &mockUsecases{}
	var gotToken, gotPassword string
	mock.redeemPasswordReset = func(ctx context.Context, token, password string) error {
		gotToken, gotPassword = token, password
		return nil
	}
	w := postJSON(testRouter(mock), "/api/v1/auth/reset", `{"token":"tok","password":"a long enough password"}`)
	require.Equal(t, http.StatusNoContent, w.Code)
	assert.Equal(t, "tok", gotToken)
	assert.Equal(t, "a long enough password", gotPassword)
	assert.Empty(t, w.Body.String())
}

func TestResetPassword_ErrorMapping(t *testing.T) {
	for name, tc := range map[string]struct {
		err    error
		status int
		code   string
	}{
		"dead link":     {usecase.ErrResetLinkInvalid, http.StatusBadRequest, "reset_link_invalid"},
		"weak password": {usecase.NewCredentialInputError("password must be at least 8 characters"), http.StatusBadRequest, "invalid_password"},
		"unexpected":    {errors.New("connection reset"), http.StatusInternalServerError, "internal_error"},
	} {
		mock := &mockUsecases{redeemPasswordReset: func(context.Context, string, string) error { return tc.err }}
		w := postJSON(testRouter(mock), "/api/v1/auth/reset", `{"token":"tok","password":"x"}`)
		assert.Equal(t, tc.status, w.Code, name)
		assert.Equal(t, tc.code, errorCodeOf(t, w), name)
	}
}

func TestResetPassword_RejectsAMalformedBody(t *testing.T) {
	w := postJSON(testRouter(&mockUsecases{}), "/api/v1/auth/reset", `not json`)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}
