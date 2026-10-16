//go:build e2e

package e2e

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestE2E_KelvinSignReachesNoAsciiAccount: U+212A lower-cases to "k" in Go and, in the stock
// postgres:17-alpine locale, in PostgreSQL's lower() as well. An address spelled with it must not
// register as, or sign in to, the plain ASCII account.
func TestE2E_KelvinSignReachesNoAsciiAccount(t *testing.T) {
	suffix := randomHex(4)
	plain := "kate" + suffix + "@example.com"
	kelvin := "Kate" + suffix + "@example.com"
	pass := "a-long-enough-password-" + randomHex(4)
	request[authResponse](t, http.MethodPost, "/api/v1/auth/register", "",
		map[string]string{"email": plain, "password": pass}, http.StatusCreated)

	// The same answer an address that is not an address gets.
	wantStatus, wantRaw := doJSON(t, http.MethodPost, "/api/v1/auth/register", "",
		map[string]string{"email": "not-an-address", "password": pass})
	require.GreaterOrEqual(t, wantStatus, 400, string(wantRaw))
	status, raw := doJSON(t, http.MethodPost, "/api/v1/auth/register", "",
		map[string]string{"email": kelvin, "password": pass})
	require.Equal(t, wantStatus, status, string(raw))
	require.Equal(t, errorCode(t, wantRaw), errorCode(t, raw))

	status, _ = doJSON(t, http.MethodPost, "/api/v1/auth/login", "",
		map[string]string{"email": kelvin, "password": pass})
	require.Equal(t, http.StatusUnauthorized, status, "the right password under the Kelvin spelling signs in to nothing")

	login(t, plain, pass)
}
