//go:build e2e

package e2e

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type resetLinkResponse struct {
	Link      string `json:"link"`
	ExpiresAt string `json:"expires_at"`
}

func resetToken(t *testing.T, link string) string {
	t.Helper()
	require.True(t, strings.HasPrefix(link, "/reset/"), link)
	return strings.TrimPrefix(link, "/reset/")
}

// TestE2E_PasswordResetLink walks the admin-issued reset against the real server: only an
// administrator can issue a link, a link works once, a newer link retires the older one, a refused
// password spends nothing, and a reset ends the account's sessions.
func TestE2E_PasswordResetLink(t *testing.T) {
	email := "reset-" + randomHex(4) + "@example.com"
	oldPass := "an-old-password-" + randomHex(4)
	session := request[authResponse](t, http.MethodPost, "/api/v1/auth/register", "",
		map[string]string{"email": email, "password": oldPass}, http.StatusCreated)
	viewerPath := "/api/v1/users/" + session.UserID + "/reset-link"

	t.Run("only an instance admin can issue a link", func(t *testing.T) {
		status, _ := doJSON(t, http.MethodPost, viewerPath, session.Token, map[string]string{})
		require.Equal(t, http.StatusForbidden, status)
		status, _ = doJSON(t, http.MethodPost, viewerPath, "", map[string]string{})
		require.Equal(t, http.StatusUnauthorized, status)
	})

	t.Run("an unknown account and a bad id are refused", func(t *testing.T) {
		status, raw := doJSON(t, http.MethodPost, "/api/v1/users/00000000-0000-4000-8000-00000000dead/reset-link", adminToken, map[string]string{})
		require.Equal(t, http.StatusNotFound, status, string(raw))
		status, _ = doJSON(t, http.MethodPost, "/api/v1/users/not-an-id/reset-link", adminToken, map[string]string{})
		require.Equal(t, http.StatusBadRequest, status)
	})

	first := request[resetLinkResponse](t, http.MethodPost, viewerPath, adminToken, map[string]string{}, http.StatusCreated)
	second := request[resetLinkResponse](t, http.MethodPost, viewerPath, adminToken, map[string]string{}, http.StatusCreated)
	require.NotEqual(t, first.Link, second.Link)

	next := "a-brand-new-password-" + randomHex(4)

	t.Run("a newer link retires the older one", func(t *testing.T) {
		status, raw := doJSON(t, http.MethodPost, "/api/v1/auth/reset", "",
			map[string]string{"token": resetToken(t, first.Link), "password": next})
		require.Equal(t, http.StatusBadRequest, status, string(raw))
		require.Equal(t, "reset_link_invalid", errorCode(t, raw))
		login(t, email, oldPass)
	})

	t.Run("a refused password leaves the link usable", func(t *testing.T) {
		status, raw := doJSON(t, http.MethodPost, "/api/v1/auth/reset", "",
			map[string]string{"token": resetToken(t, second.Link), "password": "short"})
		require.Equal(t, http.StatusBadRequest, status, string(raw))
		require.Equal(t, "invalid_password", errorCode(t, raw))
	})

	t.Run("an unknown token answers like a used one", func(t *testing.T) {
		status, raw := doJSON(t, http.MethodPost, "/api/v1/auth/reset", "",
			map[string]string{"token": "no-such-token", "password": next})
		require.Equal(t, http.StatusBadRequest, status, string(raw))
		require.Equal(t, "reset_link_invalid", errorCode(t, raw))
	})

	t.Run("redeeming sets the password, ends the sessions and works once", func(t *testing.T) {
		status, raw := doJSON(t, http.MethodPost, "/api/v1/auth/reset", "",
			map[string]string{"token": resetToken(t, second.Link), "password": next})
		require.Equal(t, http.StatusNoContent, status, string(raw))

		status, _ = doJSON(t, http.MethodGet, "/api/v1/me", session.Token, nil)
		require.Equal(t, http.StatusUnauthorized, status, "the old session ends")
		status, _ = doJSON(t, http.MethodPost, "/api/v1/auth/login", "",
			map[string]string{"email": email, "password": oldPass})
		require.Equal(t, http.StatusUnauthorized, status, "the old password stops working")
		login(t, email, next)

		status, raw = doJSON(t, http.MethodPost, "/api/v1/auth/reset", "",
			map[string]string{"token": resetToken(t, second.Link), "password": next + "x"})
		require.Equal(t, http.StatusBadRequest, status, string(raw))
		require.Equal(t, "reset_link_invalid", errorCode(t, raw))
		login(t, email, next)
	})
}

// TestE2E_ResetLinkDiesWithTheStateItWasIssuedIn pins the events that end a link: a link issued
// before the account was deactivated, or before its password changed, no longer redeems, and
// reactivating the account does not bring it back.
func TestE2E_ResetLinkDiesWithTheStateItWasIssuedIn(t *testing.T) {
	redeemRefused := func(t *testing.T, link resetLinkResponse, why string) {
		t.Helper()
		status, raw := doJSON(t, http.MethodPost, "/api/v1/auth/reset", "",
			map[string]string{"token": resetToken(t, link.Link), "password": "chosen-by-link-holder-" + randomHex(4)})
		require.Equal(t, http.StatusBadRequest, status, why+": "+string(raw))
		require.Equal(t, "reset_link_invalid", errorCode(t, raw), why)
	}

	t.Run("deactivation", func(t *testing.T) {
		email := "reset-deact-" + randomHex(4) + "@example.com"
		pass := "an-old-password-" + randomHex(4)
		u := request[authResponse](t, http.MethodPost, "/api/v1/auth/register", "",
			map[string]string{"email": email, "password": pass}, http.StatusCreated)
		link := request[resetLinkResponse](t, http.MethodPost, "/api/v1/users/"+u.UserID+"/reset-link",
			adminToken, map[string]string{}, http.StatusCreated)
		status, raw := doJSON(t, http.MethodPost, "/api/v1/users/"+u.UserID+"/deactivate", adminToken, nil)
		require.Equal(t, http.StatusOK, status, string(raw))

		redeemRefused(t, link, "deactivated")
		status, raw = doJSON(t, http.MethodPost, "/api/v1/users/"+u.UserID+"/reactivate", adminToken, nil)
		require.Equal(t, http.StatusOK, status, string(raw))
		redeemRefused(t, link, "after reactivation")
		login(t, email, pass)
	})

	t.Run("password change", func(t *testing.T) {
		email := "reset-change-" + randomHex(4) + "@example.com"
		pass := "an-old-password-" + randomHex(4)
		next := "a-newer-password-" + randomHex(4)
		u := request[authResponse](t, http.MethodPost, "/api/v1/auth/register", "",
			map[string]string{"email": email, "password": pass}, http.StatusCreated)
		link := request[resetLinkResponse](t, http.MethodPost, "/api/v1/users/"+u.UserID+"/reset-link",
			adminToken, map[string]string{}, http.StatusCreated)
		status, raw := doJSON(t, http.MethodPut, "/api/v1/me/password", u.Token,
			map[string]string{"current_password": pass, "new_password": next})
		require.Equal(t, http.StatusOK, status, string(raw))

		redeemRefused(t, link, "after the owner changed the password")
		login(t, email, next)
	})
}
