package server

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/audit"
	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
	"github.com/minh-tg/specht/internal/usecase"
)

func requireRetryAnswer(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	require.Equal(t, http.StatusServiceUnavailable, w.Code, w.Body.String())
	assert.Equal(t, "1", w.Header().Get("Retry-After"))
	assert.Contains(t, w.Body.String(), `"retry_later"`)
}

// A transaction the database ended as a deadlock victim saved nothing, so the
// routes that take account and project locks answer 503 with a retry code
// instead of a 500.
func TestDeadlockVictimAnswers503OnTheLockingRoutes(t *testing.T) {
	retry := fmt.Errorf("deactivate user: %w", port.ErrRetry)

	t.Run("deactivate user", func(t *testing.T) {
		h := NewHandler(&mockUsecases{
			deactivateUserFn: func(context.Context, string) (*usecase.UserProfile, []usecase.RevokedAPIKey, error) {
				return nil, nil, retry
			},
		})
		h.audit = audit.NewLogger(slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
		r := chi.NewRouter()
		r.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ctx := auth.ContextWithIdentity(r.Context(), &auth.Identity{UserID: "admin-1", Role: auth.RoleAdmin})
				next.ServeHTTP(w, r.WithContext(ctx))
			})
		})
		r.Post("/api/v1/users/{id}/deactivate", h.DeactivateUser)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest("POST", "/api/v1/users/u2/deactivate", nil))
		requireRetryAnswer(t, w)
	})

	t.Run("project membership", func(t *testing.T) {
		w := httptest.NewRecorder()
		respondMemberError(w, retry)
		requireRetryAnswer(t, w)
	})

	t.Run("invite", func(t *testing.T) {
		h := NewHandler(&mockUsecases{})
		w := httptest.NewRecorder()
		h.respondInviteError(w, httptest.NewRequest("POST", "/", nil), "accept", retry)
		requireRetryAnswer(t, w)
	})
}
