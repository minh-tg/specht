//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// projectSummaryRow keeps gate and stats raw so the test compares the exact
// JSON the per-project endpoints send.
type projectSummaryRow struct {
	Slug  string          `json:"slug"`
	Gate  json.RawMessage `json:"gate"`
	Stats json.RawMessage `json:"stats"`
}

func summariesBySlug(t *testing.T, token string) map[string]projectSummaryRow {
	t.Helper()
	rows := request[[]projectSummaryRow](t, http.MethodGet, "/api/v1/project-summaries", token, nil, http.StatusOK)
	out := make(map[string]projectSummaryRow, len(rows))
	for _, row := range rows {
		out[row.Slug] = row
	}
	return out
}

func decodeAny(t *testing.T, raw []byte) any {
	t.Helper()
	var v any
	require.NoError(t, json.Unmarshal(raw, &v), "%s", raw)
	return v
}

// requireRowMatchesEndpoints checks that a summary row holds what
// GET /projects/{slug}/gate and /stats answer the same caller.
func requireRowMatchesEndpoints(t *testing.T, row projectSummaryRow, token string) {
	t.Helper()
	status, gate := doJSON(t, http.MethodGet, "/api/v1/projects/"+row.Slug+"/gate", token, nil)
	require.Equal(t, http.StatusOK, status, "%s", gate)
	status, stats := doJSON(t, http.MethodGet, "/api/v1/projects/"+row.Slug+"/stats", token, nil)
	require.Equal(t, http.StatusOK, status, "%s", stats)
	require.Equal(t, decodeAny(t, gate), decodeAny(t, row.Gate), "gate of %s", row.Slug)
	require.Equal(t, decodeAny(t, stats), decodeAny(t, row.Stats), "stats of %s", row.Slug)
}

func TestE2E_ProjectSummaries(t *testing.T) {
	scanned := newProject(t, "summary-scanned")
	empty := newProject(t, "summary-empty")
	key := mintKey(t, scanned)
	ingestFixture(t, scanned, key, "high-medium.sarif.json")

	member := azRegister(t, "summary-member")
	request[memberResponse](t, http.MethodPost, "/api/v1/projects/"+scanned+"/members", adminToken,
		map[string]string{"user_id": member.UserID, "role": "member"}, http.StatusCreated)

	t.Run("admin rows equal the per-project endpoints", func(t *testing.T) {
		rows := summariesBySlug(t, adminToken)
		require.Contains(t, rows, scanned)
		require.Contains(t, rows, empty)
		requireRowMatchesEndpoints(t, rows[scanned], adminToken)
		requireRowMatchesEndpoints(t, rows[empty], adminToken)

		var gate gateStatus
		require.NoError(t, json.Unmarshal(rows[scanned].Gate, &gate))
		require.True(t, gate.ThresholdBreached, "the high finding blocks")
		require.NotEmpty(t, gate.BlockedBy)
	})

	t.Run("a member sees only their projects", func(t *testing.T) {
		rows := summariesBySlug(t, member.Token)
		require.Len(t, rows, 1)
		require.Contains(t, rows, scanned)
		requireRowMatchesEndpoints(t, rows[scanned], member.Token)
	})

	t.Run("a read key sees its own project", func(t *testing.T) {
		rows := summariesBySlug(t, key)
		require.Len(t, rows, 1)
		require.Contains(t, rows, scanned)
		requireRowMatchesEndpoints(t, rows[scanned], key)
	})

	t.Run("a key without read scope is refused", func(t *testing.T) {
		created := request[apiKeyResponse](t, http.MethodPost, "/api/v1/auth/apikeys", adminToken,
			map[string]string{"project": scanned, "name": "e2e-ingest-" + randomHex(3)}, http.StatusCreated)
		_, err := openE2EDB(t).Exec(context.Background(),
			`UPDATE api_keys SET scopes = '["ingest"]'::jsonb WHERE id = $1`, created.ID)
		require.NoError(t, err)

		status, raw := doJSON(t, http.MethodGet, "/api/v1/project-summaries", created.RawKey, nil)
		require.Equal(t, http.StatusForbidden, status, "%s", raw)
		require.Equal(t, "insufficient_scope", errorCode(t, raw))
		status, _ = doJSON(t, http.MethodGet, "/api/v1/projects/"+scanned+"/gate", created.RawKey, nil)
		require.Equal(t, http.StatusForbidden, status, "the per-project gate refuses the same key")
	})
}
