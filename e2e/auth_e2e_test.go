//go:build e2e

package e2e

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestE2E_AuthBootstrapAndSessionLifecycle walks the real account lifecycle:
// register → ADMIN_EMAILS promotion across a restart → login → profile →
// refresh-token rotation → logout. It also pins the platform-authority
// boundaries: viewer sessions and project-scoped API keys can never create
// projects.
func TestE2E_AuthBootstrapAndSessionLifecycle(t *testing.T) {
	t.Run("admin bootstrap promotion is visible in profile", func(t *testing.T) {
		// TestMain registered the account before restarting with
		// ADMIN_EMAILS, so the restart must have promoted it.
		me := request[userProfile](t, http.MethodGet, "/api/v1/me", adminToken, nil, http.StatusOK)
		require.Equal(t, adminEmail, me.Email)
		require.Equal(t, "admin", me.Role)
	})

	t.Run("wrong password is rejected without revealing the account", func(t *testing.T) {
		status, raw := doJSON(t, http.MethodPost, "/api/v1/auth/login", "",
			map[string]string{"email": adminEmail, "password": "wrong-password-1"})
		require.Equal(t, http.StatusUnauthorized, status)
		require.Contains(t, string(raw), "login_failed")
	})

	t.Run("duplicate registration is rejected generically", func(t *testing.T) {
		status, raw := doJSON(t, http.MethodPost, "/api/v1/auth/register", "",
			map[string]string{"email": adminEmail, "password": "another-password-1"})
		require.Equal(t, http.StatusUnprocessableEntity, status)
		require.Contains(t, string(raw), "registration_failed")
	})

	t.Run("viewer cannot create projects", func(t *testing.T) {
		viewerToken := login(t, "e2e-viewer@example.com", adminPass)
		status, raw := doJSON(t, http.MethodPost, "/api/v1/projects", viewerToken,
			map[string]string{"name": "viewer-project", "slug": "e2e-viewer-project"})
		require.Equal(t, http.StatusForbidden, status)
		require.Contains(t, string(raw), "insufficient_role")
	})

	t.Run("api key cannot create projects", func(t *testing.T) {
		slug := newProject(t, "key-authz")
		key := mintKey(t, slug)
		status, raw := doJSON(t, http.MethodPost, "/api/v1/projects", key,
			map[string]string{"name": "key-project", "slug": "e2e-key-project"})
		require.Equal(t, http.StatusForbidden, status)
		require.Contains(t, string(raw), "insufficient_role")
	})

	t.Run("unauthenticated requests are rejected", func(t *testing.T) {
		status, raw := doJSON(t, http.MethodGet, "/api/v1/projects", "", nil)
		require.Equal(t, http.StatusUnauthorized, status)
		require.Contains(t, string(raw), "missing_token")
	})

	t.Run("refresh tokens rotate and logout revokes the family", func(t *testing.T) {
		first := request[authResponse](t, http.MethodPost, "/api/v1/auth/login", "",
			map[string]string{"email": adminEmail, "password": adminPass}, http.StatusOK)
		require.NotEmpty(t, first.RefreshToken, "login must mint a refresh token")

		rotated := request[authResponse](t, http.MethodPost, "/api/v1/auth/refresh", "",
			map[string]string{"refresh_token": first.RefreshToken}, http.StatusOK)
		require.NotEmpty(t, rotated.Token)
		require.NotEqual(t, first.RefreshToken, rotated.RefreshToken, "refresh must rotate")

		// Replaying the consumed token revokes the whole family (M3).
		status, raw := doJSON(t, http.MethodPost, "/api/v1/auth/refresh", "",
			map[string]string{"refresh_token": first.RefreshToken})
		require.Equal(t, http.StatusUnauthorized, status)
		require.Contains(t, string(raw), "refresh_failed")

		fresh := request[authResponse](t, http.MethodPost, "/api/v1/auth/login", "",
			map[string]string{"email": adminEmail, "password": adminPass}, http.StatusOK)
		status, _ = doJSON(t, http.MethodPost, "/api/v1/auth/logout", "",
			map[string]string{"refresh_token": fresh.RefreshToken})
		require.Equal(t, http.StatusNoContent, status)

		status, raw = doJSON(t, http.MethodPost, "/api/v1/auth/refresh", "",
			map[string]string{"refresh_token": fresh.RefreshToken})
		require.Equal(t, http.StatusUnauthorized, status)
		require.Contains(t, string(raw), "refresh_failed")
	})
}
