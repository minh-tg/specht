//go:build e2e

package e2e

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type policySession struct {
	Token  string `json:"token"`
	UserID string `json:"user_id"`
	Link   string `json:"link"`
}

// TestE2E_PasswordPolicy walks every way of choosing a password against the
// real server: setup, registration, an invite, a password change and a reset
// link each refuse a listed password with password_too_common, the paths that
// know the account refuse its email or name with password_matches_account,
// and each accepts an unlisted password. A refusal spends neither the setup
// token, the invite nor the reset link.
func TestE2E_PasswordPolicy(t *testing.T) {
	const setupToken = "password-policy-setup-token-01"
	srv := startFreshServer(t, "specht_password_policy", "SETUP_TOKEN="+setupToken, "REGISTRATION_ENABLED=true")

	refused := func(t *testing.T, method, path, token string, body map[string]any, wantStatus int, wantCode string) string {
		t.Helper()
		status, _, raw := srv.do(t, method, path, token, body)
		require.Equal(t, wantStatus, status, string(raw))
		require.Equal(t, wantCode, errorCode(t, raw), string(raw))
		var e apiError
		require.NoError(t, json.Unmarshal(raw, &e))
		return e.Error.Message
	}
	accepted := func(t *testing.T, method, path, token string, body map[string]any, wantStatus int) policySession {
		t.Helper()
		status, _, raw := srv.do(t, method, path, token, body)
		require.Equal(t, wantStatus, status, string(raw))
		var out policySession
		if len(raw) > 0 {
			require.NoError(t, json.Unmarshal(raw, &out), string(raw))
		}
		return out
	}

	var admin policySession
	t.Run("setup", func(t *testing.T) {
		body := func(password string) map[string]any {
			return map[string]any{"token": setupToken, "email": "root@example.com", "password": password, "display_name": "Grace Hopper"}
		}
		refused(t, http.MethodPost, "/api/v1/setup", "", body("Password1"), http.StatusBadRequest, "password_too_common")
		refused(t, http.MethodPost, "/api/v1/setup", "", body("grace hopper"), http.StatusBadRequest, "password_matches_account")
		message := refused(t, http.MethodPost, "/api/v1/setup", "", body(strings.Repeat("😀", 19)), http.StatusBadRequest, "invalid_credentials")
		require.Contains(t, message, "72 bytes", "the limit names the unit it counts")
		required, _ := srv.setupRequired(t)
		require.True(t, required, "a refused password leaves setup open")
		admin = accepted(t, http.MethodPost, "/api/v1/setup", "", body("compiler-at-sea-1952"), http.StatusCreated)
	})
	require.NotEmpty(t, admin.Token)

	var member policySession
	const memberEmail = "ada.lovelace@example.com"
	t.Run("register", func(t *testing.T) {
		register := func(email, password string) map[string]any {
			return map[string]any{"email": email, "password": password}
		}
		refused(t, http.MethodPost, "/api/v1/auth/register", "", register(memberEmail, "12345678"), http.StatusBadRequest, "password_too_common")
		refused(t, http.MethodPost, "/api/v1/auth/register", "", register(memberEmail, "Ada.Lovelace"), http.StatusBadRequest, "password_matches_account")

		// A taken address answers a listed password the same way a new one
		// does, and a good password still gets only the generic refusal.
		refused(t, http.MethodPost, "/api/v1/auth/register", "", register("root@example.com", "12345678"), http.StatusBadRequest, "password_too_common")
		refused(t, http.MethodPost, "/api/v1/auth/register", "", register("root@example.com", "analytical-engine-43"), http.StatusUnprocessableEntity, "registration_failed")

		member = accepted(t, http.MethodPost, "/api/v1/auth/register", "", register(memberEmail, "analytical-engine-43"), http.StatusCreated)
	})
	require.NotEmpty(t, member.Token)

	t.Run("invite join", func(t *testing.T) {
		accepted(t, http.MethodPost, "/api/v1/projects", admin.Token, map[string]any{"name": "Payments", "slug": "payments"}, http.StatusCreated)
		invite := accepted(t, http.MethodPost, "/api/v1/projects/payments/invites", admin.Token, map[string]any{"role": "member"}, http.StatusCreated)
		path := "/api/v1/invites/" + strings.TrimPrefix(invite.Link, "/invite/") + "/accept"

		refused(t, http.MethodPost, path, "", map[string]any{"email": "dev@example.com", "password": "qwertyuiop"}, http.StatusBadRequest, "password_too_common")
		refused(t, http.MethodPost, path, "", map[string]any{"email": "dev@example.com", "password": "DEV@example.com"}, http.StatusBadRequest, "password_matches_account")
		refused(t, http.MethodPost, path, "", map[string]any{"email": "dev@example.com", "password": "Linus Torvalds", "display_name": "Linus Torvalds"}, http.StatusBadRequest, "password_matches_account")
		accepted(t, http.MethodPost, path, "", map[string]any{"email": "dev@example.com", "password": "kernel-panic-in-1991"}, http.StatusCreated)
	})

	t.Run("change password", func(t *testing.T) {
		change := func(next string) map[string]any {
			return map[string]any{"current_password": "analytical-engine-43", "new_password": next}
		}
		refused(t, http.MethodPut, "/api/v1/me/password", member.Token, change("iloveyou"), http.StatusBadRequest, "password_too_common")
		refused(t, http.MethodPut, "/api/v1/me/password", member.Token, change(memberEmail), http.StatusBadRequest, "password_matches_account")
		member = accepted(t, http.MethodPut, "/api/v1/me/password", member.Token, change("difference-engine-22"), http.StatusOK)
	})

	t.Run("reset link", func(t *testing.T) {
		link := accepted(t, http.MethodPost, "/api/v1/users/"+member.UserID+"/reset-link", admin.Token, map[string]any{}, http.StatusCreated)
		token := strings.TrimPrefix(link.Link, "/reset/")

		refused(t, http.MethodPost, "/api/v1/auth/reset", "", map[string]any{"token": token, "password": "football"}, http.StatusBadRequest, "password_too_common")
		accepted(t, http.MethodPost, "/api/v1/auth/reset", "", map[string]any{"token": token, "password": "notes-on-the-engine"}, http.StatusNoContent)
		accepted(t, http.MethodPost, "/api/v1/auth/login", "", map[string]any{"email": memberEmail, "password": "notes-on-the-engine"}, http.StatusOK)
	})
}
