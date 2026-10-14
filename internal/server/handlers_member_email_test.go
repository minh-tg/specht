package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/minh-tg/specht/internal/usecase"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func postJSON(router http.Handler, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func TestAddProjectMember_ByEmailGoesToTheEmailUsecase(t *testing.T) {
	mock := memberErrorMock()
	var gotEmail, gotRole string
	mock.addProjectMemberByEmail = func(ctx context.Context, slug, email, role string) (*usecase.ProjectMemberResponse, error) {
		gotEmail, gotRole = email, role
		return &usecase.ProjectMemberResponse{UserID: "u1", Role: role}, nil
	}
	w := postJSON(authRouter(NewHandler(mock)), "/api/v1/projects/my-app/members",
		`{"email":"ada@acme.example","role":"member"}`)
	require.Equal(t, http.StatusCreated, w.Code)
	assert.Equal(t, "ada@acme.example", gotEmail)
	assert.Equal(t, "member", gotRole)
}

func TestAddProjectMember_NeedsExactlyOneOfUserIDAndEmail(t *testing.T) {
	router := authRouter(NewHandler(memberErrorMock()))
	for name, body := range map[string]string{
		"neither": `{"role":"member"}`,
		"both":    `{"user_id":"00000000-0000-0000-0000-000000000002","email":"ada@acme.example","role":"member"}`,
		"no role": `{"email":"ada@acme.example"}`,
	} {
		w := postJSON(router, "/api/v1/projects/my-app/members", body)
		assert.Equal(t, http.StatusBadRequest, w.Code, name)
		assert.Equal(t, "missing_field", errorCodeOf(t, w), name)
	}
}

func TestAddProjectMember_ByEmailErrorMapping(t *testing.T) {
	for name, tc := range map[string]struct {
		err      error
		status   int
		wantCode string
	}{
		"malformed": {usecase.ErrInvalidMemberEmail, http.StatusBadRequest, "invalid_email"},
		"unknown":   {usecase.ErrMemberUserNotFound, http.StatusNotFound, "user_not_found"},
		"denied":    {usecase.ErrProjectAccessDenied, http.StatusForbidden, "project_access_denied"},
	} {
		mock := memberErrorMock()
		mock.addProjectMemberByEmail = func(context.Context, string, string, string) (*usecase.ProjectMemberResponse, error) {
			return nil, tc.err
		}
		w := postJSON(authRouter(NewHandler(mock)), "/api/v1/projects/my-app/members",
			`{"email":"ada@acme.example","role":"member"}`)
		assert.Equal(t, tc.status, w.Code, name)
		assert.Equal(t, tc.wantCode, errorCodeOf(t, w), name)
	}
}

func TestAddTeamMember_ByEmailGoesToTheEmailUsecase(t *testing.T) {
	mock := &mockUsecases{}
	var gotEmail string
	mock.addTeamMemberByEmail = func(ctx context.Context, teamID, email, role string) (*usecase.TeamMemberResponse, error) {
		gotEmail = email
		return &usecase.TeamMemberResponse{TeamID: teamID, UserID: "u1", Role: role}, nil
	}
	w := postJSON(testRouter(mock), "/api/v1/teams/11111111-1111-1111-1111-111111111111/members",
		`{"email":"ada@acme.example","role":"member"}`)
	require.Equal(t, http.StatusCreated, w.Code)
	assert.Equal(t, "ada@acme.example", gotEmail)

	w = postJSON(testRouter(mock), "/api/v1/teams/11111111-1111-1111-1111-111111111111/members",
		`{"user_id":"00000000-0000-0000-0000-000000000002","email":"ada@acme.example","role":"member"}`)
	assert.Equal(t, http.StatusBadRequest, w.Code, "naming the person twice is ambiguous")

	mock.addTeamMemberByEmail = func(context.Context, string, string, string) (*usecase.TeamMemberResponse, error) {
		return nil, usecase.ErrInvalidMemberEmail
	}
	w = postJSON(testRouter(mock), "/api/v1/teams/11111111-1111-1111-1111-111111111111/members",
		`{"email":"nope","role":"member"}`)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, "invalid_email", errorCodeOf(t, w))
}
