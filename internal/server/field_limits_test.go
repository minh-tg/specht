package server

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/usecase"
)

func TestCreateAPIKey_InvalidFieldAnswers400(t *testing.T) {
	mock := &mockUsecases{
		createAPIKeyFn: func(context.Context, string, string, *time.Time) (*usecase.APIKeyResponse, error) {
			return nil, fmt.Errorf("%w: name must be at most 100 characters", usecase.ErrInvalidField)
		},
	}
	req := httptest.NewRequest("POST", "/api/v1/auth/apikeys", strings.NewReader(`{"project":"my-app","name":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(auth.ContextWithIdentity(req.Context(), &auth.Identity{UserID: "test-user"}))
	w := httptest.NewRecorder()
	testRouter(mock).ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), `"code":"invalid_field"`)
}

func TestUpdateProject_InvalidNameOrDescriptionAnswers400(t *testing.T) {
	mock := &mockUsecases{
		updateProjectFn: func(context.Context, string, *string, *string, *string) (*usecase.ProjectResponse, error) {
			return nil, fmt.Errorf("%w: description must be at most 2000 characters", usecase.ErrInvalidField)
		},
	}
	req := httptest.NewRequest("PUT", "/api/v1/projects/my-app", strings.NewReader(`{"description":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	testRouter(mock).ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), `"code":"invalid_field"`)
	assert.Contains(t, w.Body.String(), "description")
}

func TestCreateProject_InvalidFieldAnswers400(t *testing.T) {
	mock := &mockUsecases{
		createProjectFn: func(context.Context, string, string, string, string) (*usecase.ProjectResponse, error) {
			return nil, fmt.Errorf("%w: name must be at most 100 characters", usecase.ErrInvalidField)
		},
	}
	req := httptest.NewRequest("POST", "/api/v1/projects", strings.NewReader(`{"name":"x","slug":"my-app"}`))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(auth.ContextWithIdentity(req.Context(), &auth.Identity{UserID: "test-user", Role: auth.RoleAdmin}))
	w := httptest.NewRecorder()
	testRouter(mock).ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), `"code":"invalid_field"`)
}
