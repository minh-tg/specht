package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/usecase"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func memberErrorCases() []struct {
	name       string
	err        error
	wantStatus int
	wantCode   string
} {
	return []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
	}{
		{"invalid role", fmt.Errorf("%w %q", usecase.ErrInvalidMemberRole, "boss"), http.StatusBadRequest, "invalid_role"},
		{"malformed user id", usecase.ErrInvalidID, http.StatusBadRequest, "invalid_id"},
		{"last admin", usecase.ErrLastAdminForbidden, http.StatusBadRequest, "last_admin"},
		{"unknown user", usecase.ErrMemberUserNotFound, http.StatusNotFound, "user_not_found"},
		{"unknown member", usecase.ErrMemberNotFound, http.StatusNotFound, "member_not_found"},
		{"denied", usecase.ErrProjectAccessDenied, http.StatusForbidden, "project_access_denied"},
		{"unexpected failure", errors.New("connection reset"), http.StatusInternalServerError, "internal_error"},
	}
}

func memberErrorMock() *mockUsecases {
	return &mockUsecases{
		getProjectFn: func(ctx context.Context, slug string) (*usecase.ProjectResponse, error) {
			return &usecase.ProjectResponse{ID: "00000000-0000-0000-0000-000000000001", Slug: slug}, nil
		},
		isProjectMemberFn: func(ctx context.Context, projectID, userID string) (bool, error) {
			return true, nil
		},
	}
}

func errorCodeOf(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	return body.Error.Code
}

func TestAddProjectMember_ErrorMapping(t *testing.T) {
	for _, tc := range memberErrorCases() {
		if errors.Is(tc.err, usecase.ErrMemberNotFound) {
			continue // removal only
		}
		t.Run(tc.name, func(t *testing.T) {
			mock := memberErrorMock()
			mock.addProjectMemberFn = func(ctx context.Context, projectSlug, userID, role string) (*usecase.ProjectMemberResponse, error) {
				return nil, tc.err
			}
			router := authRouter(NewHandler(mock))
			req := httptest.NewRequest("POST", "/api/v1/projects/my-app/members",
				strings.NewReader(`{"user_id":"00000000-0000-0000-0000-000000000002","role":"member"}`))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			assert.Equal(t, tc.wantStatus, w.Code)
			assert.Equal(t, tc.wantCode, errorCodeOf(t, w))
		})
	}
}

func TestRemoveProjectMember_ErrorMapping(t *testing.T) {
	for _, tc := range memberErrorCases() {
		if errors.Is(tc.err, usecase.ErrInvalidMemberRole) || errors.Is(tc.err, usecase.ErrMemberUserNotFound) {
			continue // grant only
		}
		t.Run(tc.name, func(t *testing.T) {
			mock := memberErrorMock()
			mock.removeProjectMemberFn = func(ctx context.Context, projectSlug, userID string) error {
				return tc.err
			}
			router := authRouter(NewHandler(mock))
			req := httptest.NewRequest("DELETE", "/api/v1/projects/my-app/members/00000000-0000-0000-0000-000000000002", nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			assert.Equal(t, tc.wantStatus, w.Code)
			assert.Equal(t, tc.wantCode, errorCodeOf(t, w))
		})
	}
}

func TestAddProjectMember_OutsiderLearnsNothingAboutTheProject(t *testing.T) {
	mock := memberErrorMock()
	mock.isProjectMemberFn = func(ctx context.Context, projectID, userID string) (bool, error) {
		return false, nil
	}
	mock.addProjectMemberFn = func(ctx context.Context, projectSlug, userID, role string) (*usecase.ProjectMemberResponse, error) {
		t.Fatal("an outsider must be stopped before the usecase runs")
		return nil, nil
	}
	h := NewHandler(mock)
	router := chi.NewRouter()
	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := auth.ContextWithIdentity(r.Context(), &auth.Identity{UserID: "outsider", Role: auth.RoleMember})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})
	router.Post("/api/v1/projects/{slug}/members", h.AddProjectMember)

	req := httptest.NewRequest("POST", "/api/v1/projects/my-app/members",
		strings.NewReader(`{"user_id":"00000000-0000-0000-0000-000000000002","role":"member"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Equal(t, "project_access_denied", errorCodeOf(t, w))
}
