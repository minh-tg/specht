//go:build e2e

package e2e

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// twoSecretsReport reads the Gitleaks fixture with two keys in one file and lets the caller edit
// the entries before they are sent.
func twoSecretsReport(t *testing.T, edit func([]map[string]any) []map[string]any) []byte {
	t.Helper()
	raw, err := os.ReadFile("../internal/parser/gitleaks/testdata/gitleaks-two-secrets.json")
	require.NoError(t, err)
	var entries []map[string]any
	require.NoError(t, json.Unmarshal(raw, &entries))
	out, err := json.Marshal(edit(entries))
	require.NoError(t, err)
	return out
}

func findingIDs(t *testing.T, slug string) map[string]bool {
	t.Helper()
	ids := map[string]bool{}
	for _, f := range listFindings(t, slug) {
		ids[f.ID] = true
	}
	return ids
}

// TestE2E_EachSecretInAFileIsItsOwnFinding walks the story behind keyed secret identity: a .env with
// two keys used to collapse into one finding. Now each key is one finding that stays put when its
// line moves, and a rotated key is a new finding.
func TestE2E_EachSecretInAFileIsItsOwnFinding(t *testing.T) {
	slug := newProject(t, "secret-identity")

	status, got := postReport(t, slug, "gitleaks", twoSecretsReport(t, func(e []map[string]any) []map[string]any { return e }))
	require.Equal(t, http.StatusCreated, status, got.Error.Message)
	first := findingIDs(t, slug)
	require.Len(t, first, 2, "two different keys are two findings")

	t.Run("the same secrets on other lines add nothing", func(t *testing.T) {
		moved := twoSecretsReport(t, func(e []map[string]any) []map[string]any {
			for _, entry := range e {
				entry["StartLine"] = entry["StartLine"].(float64) + 30
				entry["EndLine"] = entry["EndLine"].(float64) + 30
				entry["Commit"] = "1111111111111111111111111111111111111111"
			}
			return e
		})
		status, got := postReport(t, slug, "gitleaks", moved)
		require.Equal(t, http.StatusCreated, status, got.Error.Message)
		require.Equal(t, first, findingIDs(t, slug), "an edit above the secrets does not make new findings")
	})

	t.Run("a rotated secret is a new finding", func(t *testing.T) {
		rotated := twoSecretsReport(t, func(e []map[string]any) []map[string]any {
			e[1]["Secret"] = "placeholder-secret-value-99"
			e[1]["Match"] = "API_KEY=placeholder-secret-value-99"
			return e
		})
		status, got := postReport(t, slug, "gitleaks", rotated)
		require.Equal(t, http.StatusCreated, status, got.Error.Message)
		now := findingIDs(t, slug)
		require.Len(t, now, 3, "the first key is unchanged, the old second key stays until resolved, the new one is added")
		for id := range first {
			require.True(t, now[id], "the original findings are still there")
		}
	})

	t.Run("no secret is kept in the stored report", func(t *testing.T) {
		reports := request[[]struct {
			ID string `json:"id"`
		}](t, http.MethodGet, "/api/v1/projects/"+slug+"/reports", adminToken, nil, http.StatusOK)
		require.NotEmpty(t, reports)
		for _, r := range reports {
			_, body := doJSON(t, http.MethodGet, "/api/v1/reports/"+r.ID, adminToken, nil)
			require.False(t, strings.Contains(string(body), "placeholder-secret-value"), "the report %s keeps a credential", r.ID)
		}
	})
}
