//go:build e2e

package e2e

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

type projectWatcher struct {
	Enabled                  bool   `json:"enabled"`
	IntervalSeconds          int    `json:"interval_seconds"`
	DefaultIntervalSeconds   int    `json:"default_interval_seconds"`
	MinIntervalSeconds       int    `json:"min_interval_seconds"`
	MaxIntervalSeconds       int    `json:"max_interval_seconds"`
	ServerEnabled            bool   `json:"server_enabled"`
	EffectiveEnabled         bool   `json:"effective_enabled"`
	EffectiveIntervalSeconds int    `json:"effective_interval_seconds"`
	Status                   string `json:"status"`
	Healthy                  bool   `json:"healthy"`
}

// settings is the stored configuration alone. Status and Healthy describe the
// watcher's last run, which the e2e server's one-second watcher can change
// between two reads, so a "nothing changed" check compares settings only.
func (w projectWatcher) settings() projectWatcher {
	w.Status, w.Healthy = "", false
	return w
}

// TestE2E_ProjectWatcherSettings walks the watcher screen's contract: any
// member reads the settings and what they amount to, a project admin changes
// them within the accepted range, and a bad request writes nothing.
func TestE2E_ProjectWatcherSettings(t *testing.T) {
	slug := newProject(t, "watcherset")
	key := mintKey(t, slug)
	path := "/api/v1/projects/" + slug + "/watcher"

	t.Run("a member reads the settings and the accepted range", func(t *testing.T) {
		w := request[projectWatcher](t, http.MethodGet, path, adminToken, nil, http.StatusOK)
		require.True(t, w.Enabled)
		require.True(t, w.ServerEnabled, "the e2e server runs the watcher")
		require.True(t, w.EffectiveEnabled)
		require.Equal(t, w.IntervalSeconds, w.EffectiveIntervalSeconds)
		require.Equal(t, 3600, w.DefaultIntervalSeconds)
		require.Equal(t, 604800, w.MaxIntervalSeconds)
		require.NotEmpty(t, w.Status)

		request[projectWatcher](t, http.MethodGet, path, key, nil, http.StatusOK)
	})

	t.Run("an outsider reads nothing and changes nothing", func(t *testing.T) {
		outsider := request[authResponse](t, http.MethodPost, "/api/v1/auth/login", "",
			map[string]string{"email": "e2e-viewer@example.com", "password": adminPass}, http.StatusOK)
		status, _ := doJSON(t, http.MethodGet, path, outsider.Token, nil)
		require.Equal(t, http.StatusForbidden, status)
		status, _ = doJSON(t, http.MethodPut, path, outsider.Token, map[string]any{"enabled": false})
		require.Equal(t, http.StatusForbidden, status)
		status, _ = doJSON(t, http.MethodPut, path, key, map[string]any{"enabled": false})
		require.Contains(t, []int{http.StatusForbidden, http.StatusUnauthorized}, status, "a project key never changes it")
		require.True(t, request[projectWatcher](t, http.MethodGet, path, adminToken, nil, http.StatusOK).Enabled)
	})

	t.Run("a bad request is refused and writes nothing", func(t *testing.T) {
		before := request[projectWatcher](t, http.MethodGet, path, adminToken, nil, http.StatusOK)
		for name, body := range map[string]map[string]any{
			"nothing to change": {},
			"zero interval":     {"interval_seconds": 0},
			"past seven days":   {"interval_seconds": 604801},
			"text interval":     {"interval_seconds": "hourly"},
			"text switch":       {"enabled": "yes"},
			"unknown field":     {"interval": 3600},
		} {
			status, raw := doJSON(t, http.MethodPut, path, adminToken, body)
			require.Equal(t, http.StatusBadRequest, status, name+": "+string(raw))
			require.Equal(t, "invalid_watcher_settings", errorCode(t, raw), name)
		}
		after := request[projectWatcher](t, http.MethodGet, path, adminToken, nil, http.StatusOK)
		require.Equal(t, before.settings(), after.settings())
	})

	t.Run("the admin switches it off, retunes it and resets it", func(t *testing.T) {
		off := request[projectWatcher](t, http.MethodPut, path, adminToken, map[string]any{"enabled": false}, http.StatusOK)
		require.False(t, off.Enabled)
		require.False(t, off.EffectiveEnabled)
		require.Equal(t, "disabled", off.Status)

		tuned := request[projectWatcher](t, http.MethodPut, path, adminToken,
			map[string]any{"enabled": true, "interval_seconds": 7200}, http.StatusOK)
		require.True(t, tuned.Enabled)
		require.Equal(t, 7200, tuned.IntervalSeconds)
		require.Equal(t, 7200, tuned.EffectiveIntervalSeconds)
		require.NotEqual(t, "disabled", tuned.Status)

		reset := request[projectWatcher](t, http.MethodPut, path, adminToken, map[string]any{"interval_seconds": nil}, http.StatusOK)
		require.Equal(t, 3600, reset.IntervalSeconds, "null returns the interval to its default")
		require.True(t, reset.Enabled, "the switch is untouched")

		stored := request[projectWatcher](t, http.MethodGet, path, adminToken, nil, http.StatusOK)
		require.Equal(t, reset.settings(), stored.settings())
	})
}
