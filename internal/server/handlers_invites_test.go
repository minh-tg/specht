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

func inviteRequest(t *testing.T, mock *mockUsecases, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	router := NewRouter(RouterConfig{Usecases: mock, JWTAuth: testJWTAuth, RegistrationDisabled: true})
	var reader *strings.Reader
	if body != "" {
		reader = strings.NewReader(body)
	} else {
		reader = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "192.0.2.78:1234"
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func TestCreateInvite_ReturnsTheLinkOnceAndNeverCachesIt(t *testing.T) {
	var gotSlug string
	var got usecase.CreateInviteInput
	mock := &mockUsecases{createInviteFn: func(_ context.Context, slug string, in usecase.CreateInviteInput) (*usecase.InviteResponse, error) {
		gotSlug, got = slug, in
		return &usecase.InviteResponse{ID: "i1", Role: in.Role, Link: "/invite/abc"}, nil
	}}

	w := inviteRequest(t, mock, "POST", "/api/v1/projects/payments/invites", testToken(t),
		`{"role":"manager","email":"a@example.com","expires_in_days":14}`)

	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	assert.Equal(t, "payments", gotSlug)
	assert.Equal(t, usecase.CreateInviteInput{Role: "manager", Email: "a@example.com", ExpiresInDays: 14}, got)
	assert.Contains(t, w.Body.String(), `"link":"/invite/abc"`)
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
}

func TestCreateInvite_NeedsASessionAndARole(t *testing.T) {
	mock := &mockUsecases{}
	w := inviteRequest(t, mock, "POST", "/api/v1/projects/payments/invites", "", `{"role":"member"}`)
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	w = inviteRequest(t, mock, "POST", "/api/v1/projects/payments/invites", testToken(t), `{}`)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "missing_field")
}

func TestInviteErrorMapping(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		status int
		code   string
	}{
		{"no access", usecase.ErrProjectAccessDenied, http.StatusForbidden, "project_access_denied"},
		{"dead link", usecase.ErrInviteNotFound, http.StatusNotFound, "not_found"},
		{"wrong address", usecase.ErrInviteEmailMismatch, http.StatusForbidden, "invite_email_mismatch"},
		{"bad role", usecase.ErrInvalidInviteRole, http.StatusBadRequest, "invalid_invite_role"},
		{"bad input", usecase.ErrInvalidInviteInput, http.StatusBadRequest, "invalid_invite"},
		{"too many", usecase.ErrTooManyInvites, http.StatusConflict, "too_many_invites"},
		{"bad id", usecase.ErrInvalidID, http.StatusBadRequest, "invalid_id"},
		{"weak password", usecase.ErrInvalidCredentialInput, http.StatusBadRequest, "invalid_credentials"},
		{"address taken looks like any failure", usecase.ErrRegistrationFailed, http.StatusUnprocessableEntity, "registration_failed"},
		{"internal detail stays internal", errors.New("pq: relation invites at 10.0.0.9"), http.StatusInternalServerError, "internal_error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mock := &mockUsecases{
				createInviteFn: func(context.Context, string, usecase.CreateInviteInput) (*usecase.InviteResponse, error) {
					return nil, tc.err
				},
			}
			w := inviteRequest(t, mock, "POST", "/api/v1/projects/payments/invites", testToken(t), `{"role":"member"}`)
			assert.Equal(t, tc.status, w.Code)
			assert.Contains(t, w.Body.String(), tc.code)
			assert.NotContains(t, w.Body.String(), "10.0.0.9")
		})
	}
}

func TestListAndRevokeInvites(t *testing.T) {
	var revoked string
	mock := &mockUsecases{
		listInvitesFn: func(context.Context, string) ([]usecase.InviteResponse, error) {
			return []usecase.InviteResponse{{ID: "i1", Role: "member"}}, nil
		},
		revokeInviteFn: func(_ context.Context, _, id string) (*usecase.InviteResponse, error) {
			revoked = id
			return &usecase.InviteResponse{ID: id}, nil
		},
	}

	w := inviteRequest(t, mock, "GET", "/api/v1/projects/payments/invites", testToken(t), "")
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"id":"i1"`)
	assert.NotContains(t, w.Body.String(), "link")

	w = inviteRequest(t, mock, "DELETE", "/api/v1/projects/payments/invites/i1", testToken(t), "")
	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Equal(t, "i1", revoked)
}

func TestLookupInvite_IsPublicAndSaysLittle(t *testing.T) {
	mock := &mockUsecases{lookupInviteFn: func(_ context.Context, token string) (*usecase.InviteLookupResponse, error) {
		if token != "good" {
			return nil, usecase.ErrInviteNotFound
		}
		return &usecase.InviteLookupResponse{ProjectName: "Payments", Role: "member"}, nil
	}}

	w := inviteRequest(t, mock, "GET", "/api/v1/invites/good", "", "")
	require.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `{"project_name":"Payments","role":"member"}`, w.Body.String())
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))

	dead := inviteRequest(t, mock, "GET", "/api/v1/invites/bad", "", "")
	assert.Equal(t, http.StatusNotFound, dead.Code)
}

func TestAcceptInvite_WorksWithRegistrationClosed(t *testing.T) {
	var gotToken string
	var got usecase.AcceptInviteInput
	mock := &mockUsecases{acceptInviteFn: func(_ context.Context, token string, in usecase.AcceptInviteInput) (*usecase.AcceptInviteResponse, error) {
		gotToken, got = token, in
		return &usecase.AcceptInviteResponse{
			AuthResponse: usecase.AuthResponse{Token: "t", RefreshToken: "r", UserID: "u1", Email: in.Email},
			ProjectSlug:  "payments", Role: "member",
		}, nil
	}}

	// The router in this helper has self-service registration switched off.
	reg := inviteRequest(t, mock, "POST", "/api/v1/auth/register", "", `{"email":"a@example.com","password":"correct-horse"}`)
	require.Equal(t, http.StatusForbidden, reg.Code)

	w := inviteRequest(t, mock, "POST", "/api/v1/invites/tok123/accept", "",
		`{"email":"new@example.com","password":"correct-horse-battery","display_name":"New"}`)

	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	assert.Equal(t, "tok123", gotToken)
	assert.Equal(t, usecase.AcceptInviteInput{Email: "new@example.com", Password: "correct-horse-battery", DisplayName: "New"}, got)
	assert.Contains(t, w.Body.String(), `"token":"t"`)
	assert.Contains(t, w.Body.String(), `"project_slug":"payments"`)
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
}

func TestJoinInvite_NeedsASession(t *testing.T) {
	mock := &mockUsecases{joinInviteFn: func(context.Context, string) (*usecase.JoinInviteResponse, error) {
		return &usecase.JoinInviteResponse{ProjectSlug: "payments", Role: "member"}, nil
	}}

	assert.Equal(t, http.StatusUnauthorized, inviteRequest(t, mock, "POST", "/api/v1/invites/tok/join", "", "").Code)

	w := inviteRequest(t, mock, "POST", "/api/v1/invites/tok/join", makeTestToken(t, "viewer"), "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.JSONEq(t, `{"project_slug":"payments","role":"member"}`, w.Body.String())
}
