package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"

	"github.com/minh-tg/specht/internal/usecase"
)

func listTeamsStatus(t *testing.T, err error) (int, string) {
	t.Helper()
	h := NewHandler(&mockUsecases{
		listTeamsFn: func(ctx context.Context) ([]usecase.TeamResponse, error) {
			return nil, err
		},
	})
	router := chi.NewRouter()
	router.Get("/api/v1/teams", h.ListTeams)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/teams", nil))
	return w.Code, errorCodeOf(t, w)
}

func TestListTeams_DenialIsForbiddenNotAServerError(t *testing.T) {
	status, code := listTeamsStatus(t, usecase.ErrProjectAccessDenied)

	assert.Equal(t, http.StatusForbidden, status)
	assert.Equal(t, "project_access_denied", code)
}

func TestListTeams_UnexpectedFailureIsAServerError(t *testing.T) {
	status, code := listTeamsStatus(t, errors.New("connection reset"))

	assert.Equal(t, http.StatusInternalServerError, status)
	assert.Equal(t, "teams_failed", code)
}
