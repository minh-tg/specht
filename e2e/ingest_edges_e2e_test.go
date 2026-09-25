//go:build e2e

package e2e

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// BP-16's server-side bad paths — the catalog's "edge cases NOT E2E'd":
// malformed bodies, the size cap, individually named missing fields,
// unknown project/scanner, and what a parse failure does or does not
// persist.

func TestE2E_IngestEdgeCases(t *testing.T) {
	slug := newProject(t, "ingest-edges")

	t.Run("malformed json is rejected before any work", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, baseURL+"/api/v1/reports",
			strings.NewReader("{not json"))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+adminToken)
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode, string(body))
		require.Equal(t, "invalid_json", errorCode(t, body))
	})

	t.Run("bodies past the cap get 413", func(t *testing.T) {
		pad := strings.Repeat("a", 25<<20+1024)
		status, raw := doJSON(t, http.MethodPost, "/api/v1/reports", adminToken,
			map[string]any{
				"project": slug, "scanner": "sarif",
				"raw_data": map[string]string{"pad": pad},
			})
		require.Equal(t, http.StatusRequestEntityTooLarge, status)
		require.Equal(t, "body_too_large", errorCode(t, raw))
	})

	t.Run("missing fields are named individually", func(t *testing.T) {
		cases := []struct {
			name string
			body map[string]any
		}{
			{"project", map[string]any{"scanner": "sarif", "raw_data": map[string]any{}}},
			{"scanner", map[string]any{"project": slug, "raw_data": map[string]any{}}},
			{"raw_data", map[string]any{"project": slug, "scanner": "sarif"}},
		}
		for _, c := range cases {
			status, raw := doJSON(t, http.MethodPost, "/api/v1/reports", adminToken, c.body)
			require.Equalf(t, http.StatusBadRequest, status, "missing %s: %s", c.name, raw)
			require.Equalf(t, "missing_field", errorCode(t, raw), "missing %s", c.name)
		}
	})

	t.Run("unknown project hides behind 404, unknown scanner fails the ingest", func(t *testing.T) {
		status, raw := doJSON(t, http.MethodPost, "/api/v1/reports", adminToken,
			map[string]any{
				"project": "no-such-" + randomHex(4), "scanner": "sarif",
				"raw_data": map[string]any{},
			})
		require.Equal(t, http.StatusNotFound, status, string(raw))
		require.Equal(t, "not_found", errorCode(t, raw))

		status, raw = doJSON(t, http.MethodPost, "/api/v1/reports", adminToken,
			map[string]any{
				"project": slug, "scanner": "no-such-scanner",
				"raw_data": map[string]any{},
			})
		require.Equal(t, http.StatusUnprocessableEntity, status, string(raw))
		require.Equal(t, "ingest_failed", errorCode(t, raw))
	})

	t.Run("a parse failure answers 422 and persists no report row", func(t *testing.T) {
		before := request[[]reportRow](t, http.MethodGet,
			"/api/v1/projects/"+slug+"/reports?limit=50", adminToken, nil, http.StatusOK)

		// trivy is a registered scanner; the payload is not a trivy report.
		status, raw := doJSON(t, http.MethodPost, "/api/v1/reports", adminToken,
			map[string]any{
				"project": slug, "scanner": "trivy",
				"raw_data": map[string]any{"Results": "not-an-array"},
			})
		require.Equal(t, http.StatusUnprocessableEntity, status, string(raw))
		require.Equal(t, "ingest_failed", errorCode(t, raw))

		after := request[[]reportRow](t, http.MethodGet,
			"/api/v1/projects/"+slug+"/reports?limit=50", adminToken, nil, http.StatusOK)
		require.Len(t, after, len(before),
			"parsing happens before report creation — a rejected payload leaves nothing behind")
	})
}
