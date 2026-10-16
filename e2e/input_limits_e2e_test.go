//go:build e2e

package e2e

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestE2E_EmailAndNameLengthCaps sends oversized emails and display names to
// the real server: registration and the profile update refuse them, and a
// value at the limit still goes through.
func TestE2E_EmailAndNameLengthCaps(t *testing.T) {
	const tail = "@example.com"
	emailOf := func(n int) string { return strings.Repeat("a", n-len(tail)-8) + randomHex(4) + tail }

	t.Run("registration refuses a 255 byte address", func(t *testing.T) {
		status, raw := doJSON(t, http.MethodPost, "/api/v1/auth/register", "",
			map[string]string{"email": emailOf(255), "password": adminPass})
		require.Equal(t, http.StatusUnprocessableEntity, status, string(raw))
		require.Equal(t, "registration_failed", errorCode(t, raw))
	})

	t.Run("registration accepts a 254 byte address", func(t *testing.T) {
		request[authResponse](t, http.MethodPost, "/api/v1/auth/register", "",
			map[string]string{"email": emailOf(254), "password": adminPass}, http.StatusCreated)
	})

	t.Run("the profile update caps the name at 100 characters", func(t *testing.T) {
		person := registerPerson(t, "name-cap")

		status, raw := doJSON(t, http.MethodPut, "/api/v1/me", person.Token,
			map[string]string{"display_name": strings.Repeat("é", 101)})
		require.Equal(t, http.StatusBadRequest, status, string(raw))
		require.Equal(t, "invalid_display_name", errorCode(t, raw))

		status, raw = doJSON(t, http.MethodPut, "/api/v1/me", person.Token,
			map[string]string{"display_name": strings.Repeat("é", 100)})
		require.Equal(t, http.StatusOK, status, string(raw))
	})
}
