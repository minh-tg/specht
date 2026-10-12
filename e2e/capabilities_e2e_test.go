//go:build e2e

package e2e

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestE2E_CapabilitiesArePublic checks what a signed-out login page reads: no
// token is needed, registration shows as open on the e2e server and SSO as
// available, and the answer holds nothing about the identity provider.
func TestE2E_CapabilitiesArePublic(t *testing.T) {
	resp, err := http.Get(baseURL + "/api/v1/capabilities")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "public, max-age=60", resp.Header.Get("Cache-Control"))

	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	var body struct {
		Registration struct {
			Enabled bool `json:"enabled"`
		} `json:"registration"`
		SSO struct {
			Enabled   bool   `json:"enabled"`
			LoginPath string `json:"login_path"`
		} `json:"sso"`
		Version string `json:"version"`
	}
	require.NoError(t, json.Unmarshal(raw, &body), string(raw))
	require.True(t, body.Registration.Enabled)
	require.NotEmpty(t, body.Version)
	if body.SSO.Enabled {
		require.Equal(t, "/api/v1/auth/sso/login", body.SSO.LoginPath)
	}
	require.NotContains(t, string(raw), "client_secret")
}
