//go:build e2e

package e2e

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func findEnvironment(t *testing.T, slug, name string) environmentRow {
	t.Helper()
	rows := request[[]environmentRow](t, http.MethodGet, "/api/v1/projects/"+slug+"/environments", adminToken, nil, http.StatusOK)
	for _, e := range rows {
		if e.Name == name {
			return e
		}
	}
	require.Failf(t, "environment missing", "%q is not among %d environments", name, len(rows))
	return environmentRow{}
}

// TestE2E_EnvironmentSettingsSurviveLaterScans walks the story behind editing an environment: a
// scan names "production", an admin marks it exposed and restricted, and the next scan of the same
// environment leaves that alone.
func TestE2E_EnvironmentSettingsSurviveLaterScans(t *testing.T) {
	slug := newProject(t, "env-edit")
	key := mintKey(t, slug)
	scan := func(commit string) {
		ingestRaw(t, slug, "trivy", "trivy-alpine-scan.json", map[string]any{"environment": "production", "commit_sha": commit})
	}
	scan(baseSHA)

	env := findEnvironment(t, slug, "production")
	require.Equal(t, "production", env.Tier, "the tier is guessed from the name")
	require.False(t, env.InternetFacing, "a scan creates the environment with plain defaults")
	require.Equal(t, "internal", env.DataSensitivity)
	path := "/api/v1/projects/" + slug + "/environments/" + env.ID
	settings := map[string]any{"tier": "production", "internet_facing": true, "data_sensitivity": "restricted"}

	t.Run("a person outside the project cannot change it", func(t *testing.T) {
		viewer := request[authResponse](t, http.MethodPost, "/api/v1/auth/login", "",
			map[string]string{"email": "e2e-viewer@example.com", "password": adminPass}, http.StatusOK)
		status, _ := doJSON(t, http.MethodPut, path, viewer.Token, settings)
		require.Equal(t, http.StatusForbidden, status)
		status, _ = doJSON(t, http.MethodPut, path, key, settings)
		require.Contains(t, []int{http.StatusForbidden, http.StatusUnauthorized}, status, "an API key never edits an environment")
		require.False(t, findEnvironment(t, slug, "production").InternetFacing)
	})

	t.Run("values outside the vocabulary and missing fields are refused", func(t *testing.T) {
		status, _ := doJSON(t, http.MethodPut, path, adminToken, map[string]any{"tier": "prod", "internet_facing": true, "data_sensitivity": "restricted"})
		require.Equal(t, http.StatusBadRequest, status)
		status, _ = doJSON(t, http.MethodPut, path, adminToken, map[string]any{"tier": "production"})
		require.Equal(t, http.StatusBadRequest, status)
	})

	t.Run("an unknown environment is not found", func(t *testing.T) {
		status, _ := doJSON(t, http.MethodPut, "/api/v1/projects/"+slug+"/environments/00000000-0000-4000-8000-00000000dead", adminToken, settings)
		require.Equal(t, http.StatusNotFound, status)
		status, _ = doJSON(t, http.MethodPut, "/api/v1/projects/"+slug+"/environments/not-a-uuid", adminToken, settings)
		require.Equal(t, http.StatusNotFound, status)
	})

	t.Run("an environment of another project is not reachable through this one", func(t *testing.T) {
		other := newProject(t, "env-other")
		status, _ := doJSON(t, http.MethodPut, "/api/v1/projects/"+other+"/environments/"+env.ID, adminToken, settings)
		require.Equal(t, http.StatusNotFound, status)
	})

	t.Run("the admin classifies it", func(t *testing.T) {
		got := request[environmentRow](t, http.MethodPut, path, adminToken, settings, http.StatusOK)
		require.Equal(t, env.ID, got.ID)
		require.Equal(t, "production", got.Tier)
		require.True(t, got.InternetFacing)
		require.Equal(t, "restricted", got.DataSensitivity)
		require.Equal(t, got, findEnvironment(t, slug, "production"))
	})

	t.Run("a later scan keeps it", func(t *testing.T) {
		scan(deadSHA)
		require.Equal(t, "restricted", findEnvironment(t, slug, "production").DataSensitivity)
		require.True(t, findEnvironment(t, slug, "production").InternetFacing)
		require.Equal(t, "production", findEnvironment(t, slug, "production").Tier)
	})

	t.Run("the change and the refusal are in the audit trail", func(t *testing.T) {
		lines := auditLines(t, "project.environment.update")
		require.NotEmpty(t, lines)
		var sawSuccess, sawFailure bool
		for _, l := range lines {
			if !strings.Contains(l, "target="+env.ID) {
				continue
			}
			sawSuccess = sawSuccess || strings.Contains(l, "outcome=success")
			sawFailure = sawFailure || strings.Contains(l, "outcome=failure")
		}
		require.True(t, sawSuccess, "the admin's change")
		require.True(t, sawFailure, "the refused attempts")
	})
}
