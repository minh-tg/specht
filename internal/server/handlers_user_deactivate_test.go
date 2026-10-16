package server

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/audit"
	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/usecase"
)

func TestDeactivateUserWritesOneAuditLinePerRevokedKey(t *testing.T) {
	var buf bytes.Buffer
	h := NewHandler(&mockUsecases{
		deactivateUserFn: func(context.Context, string) (*usecase.UserProfile, []usecase.RevokedAPIKey, error) {
			return &usecase.UserProfile{ID: "u2", Disabled: true}, []usecase.RevokedAPIKey{
				{ID: "key-1", ProjectSlug: "my-app", Name: "ci"},
				{ID: "key-2", ProjectSlug: "other-app", Name: "deploy"},
			}, nil
		},
	})
	h.audit = audit.NewLogger(slog.New(slog.NewTextHandler(&buf, nil)))
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
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	logged := buf.String()
	assert.Equal(t, 1, strings.Count(logged, "audit=user.deactivate"))
	assert.Equal(t, 2, strings.Count(logged, "audit=auth.apikey.revoke"), "one line per revoked key")
	assert.Contains(t, logged, "project=my-app target=key-1")
	assert.Contains(t, logged, "project=other-app target=key-2")
	assert.Contains(t, logged, "principal_id=admin-1")
}
