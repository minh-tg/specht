//go:build e2e

package e2e

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// A login finishes in the browser that started it. The exchange code leaves
// the callback URL and can end up in a shared link or a log, but only the
// browser that holds the login cookie can redeem it.
func TestE2E_SSOCodeNeedsTheStartingBrowser(t *testing.T) {
	fakes.idp.setEmail("e2e-browser-binding@example.com")
	status, location, cookies := ssoExchange(t, "")
	code := ssoCodeFrom(t, status, location)
	loginCookie := ssoStateCookie(cookies)
	require.NotNil(t, loginCookie, "the flow binds the login to a cookie")

	t.Run("a browser without the login cookie is refused", func(t *testing.T) {
		st, body, _ := exchangeCode(t, code)
		require.Equal(t, http.StatusForbidden, st, string(body))
		require.Contains(t, string(body), "sso_browser_mismatch")
	})

	t.Run("a browser holding another login's cookie is refused", func(t *testing.T) {
		_, otherCookies, _ := ssoLoginLeg(t, "")
		st, body, _ := exchangeCode(t, code, otherCookies...)
		require.Equal(t, http.StatusForbidden, st, string(body))
		require.Contains(t, string(body), "sso_browser_mismatch")
	})

	t.Run("the refused attempts did not spend the code: the starting browser completes the login", func(t *testing.T) {
		st, body, setCookies := exchangeCode(t, code, cookies...)
		require.Equal(t, http.StatusOK, st, string(body))

		var resp struct {
			Token string `json:"token"`
		}
		require.NoError(t, json.Unmarshal(body, &resp))
		require.NotEmpty(t, resp.Token)
		request[profileEnvelope](t, http.MethodGet, "/api/v1/me", resp.Token, nil, http.StatusOK)

		var cleared bool
		for _, c := range setCookies {
			if c.Name == loginCookie.Name && c.MaxAge < 0 {
				cleared = true
			}
		}
		require.True(t, cleared, "the redeemed login cookie is deleted")
	})

	t.Run("the redeemed code cannot be used again", func(t *testing.T) {
		st, body, _ := exchangeCode(t, code, cookies...)
		require.Equal(t, http.StatusUnauthorized, st, string(body))
		require.Contains(t, string(body), "invalid_code")
	})
}
