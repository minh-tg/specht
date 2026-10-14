package server

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/auth"
)

// captureAudit points the default logger at a buffer for the test and returns a reader for the
// audit entries written to it.
func captureAudit(t *testing.T) func() []map[string]any {
	t.Helper()
	var buf bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return func() []map[string]any {
		var out []map[string]any
		for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
			if line == "" {
				continue
			}
			var entry map[string]any
			require.NoError(t, json.Unmarshal([]byte(line), &entry))
			if entry["audit"] != nil {
				out = append(out, entry)
			}
		}
		return out
	}
}

func auditedRouter(status int) http.Handler {
	h := NewHandler(&mockUsecases{})
	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			ctx := auth.ContextWithIdentity(req.Context(), &auth.Identity{UserID: "u-admin", Role: auth.RoleAdmin})
			next.ServeHTTP(w, req.WithContext(ctx))
		})
	})
	r.With(h.audited("member.add", "userID")).Post("/p/{slug}/members/{userID}", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
	})
	r.With(h.audited("team.delete", "id")).Delete("/teams/{id}", func(w http.ResponseWriter, _ *http.Request) {
		// A handler that never calls WriteHeader answers 200.
		_, _ = w.Write([]byte("ok"))
	})
	return r
}

func TestAudited_RecordsWhoDidWhatToWhatAndHowItEnded(t *testing.T) {
	for name, tc := range map[string]struct {
		status  int
		outcome string
	}{
		"created":   {http.StatusCreated, "success"},
		"refused":   {http.StatusForbidden, "failure"},
		"not found": {http.StatusNotFound, "failure"},
		"broken":    {http.StatusInternalServerError, "error"},
	} {
		entries := captureAudit(t)
		req := httptest.NewRequest("POST", "/p/payments/members/u-9", nil)
		rec := httptest.NewRecorder()
		auditedRouter(tc.status).ServeHTTP(rec, req)

		got := entries()
		require.Len(t, got, 1, name)
		assert.Equal(t, "member.add", got[0]["audit"], name)
		assert.Equal(t, tc.outcome, got[0]["outcome"], name)
		assert.Equal(t, "u-admin", got[0]["principal_id"], name)
		assert.Equal(t, "payments", got[0]["project"], name)
		assert.Equal(t, "u-9", got[0]["target"], name)
	}
}

func TestAudited_TreatsAnImplicitOKAsSuccess(t *testing.T) {
	entries := captureAudit(t)
	rec := httptest.NewRecorder()
	auditedRouter(0).ServeHTTP(rec, httptest.NewRequest("DELETE", "/teams/t-1", nil))

	got := entries()
	require.Len(t, got, 1)
	assert.Equal(t, "success", got[0]["outcome"])
	assert.Equal(t, "t-1", got[0]["target"])
	assert.Equal(t, "", got[0]["project"], "a route without a slug names no project")
}

func TestAudited_AHandlerCanNameTheTargetItResolved(t *testing.T) {
	entries := captureAudit(t)
	h := NewHandler(&mockUsecases{})
	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			ctx := auth.ContextWithIdentity(req.Context(), &auth.Identity{UserID: "u-admin", Role: auth.RoleAdmin})
			next.ServeHTTP(w, req.WithContext(ctx))
		})
	})
	r.With(h.audited("member.add", "userID")).Post("/p/{slug}/members", func(w http.ResponseWriter, req *http.Request) {
		setAuditTarget(req, "u-resolved")
		w.WriteHeader(http.StatusCreated)
	})
	r.Post("/plain", func(w http.ResponseWriter, req *http.Request) {
		setAuditTarget(req, "ignored")
		w.WriteHeader(http.StatusNoContent)
	})

	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/p/payments/members", nil))
	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/plain", nil))

	got := entries()
	require.Len(t, got, 1, "an unaudited route writes nothing and setAuditTarget is harmless there")
	assert.Equal(t, "u-resolved", got[0]["target"])
}
