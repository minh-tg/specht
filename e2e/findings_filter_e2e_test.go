//go:build e2e

package e2e

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// findingsPage reads one findings page and returns the X-Total-Count header
// alongside it, where the size of the filtered set lives.
func findingsPage(t *testing.T, slug, query string) ([]scanFinding, string) {
	t.Helper()
	path := baseURL + "/api/v1/projects/" + slug + "/findings"
	if query != "" {
		path += "?" + query
	}
	req, err := http.NewRequest(http.MethodGet, path, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	var out []scanFinding
	require.NoErrorf(t, json.Unmarshal(raw, &out), "decode %s", raw)
	return out, resp.Header.Get("X-Total-Count")
}

// listFindingsPage reads the findings list with an explicit query string so
// a test can exercise filters and pagination bounds.
func listFindingsPage(t *testing.T, slug, query string) []scanFinding {
	t.Helper()
	path := "/api/v1/projects/" + slug + "/findings"
	if query != "" {
		path += "?" + query
	}
	return request[[]scanFinding](t, http.MethodGet, path, adminToken, nil, http.StatusOK)
}

// TestE2E_FindingsFiltersAndPagination pins the list contract's selection
// and windowing: kind, severity, and status filters compose, limit and
// offset bound the page, and a malformed or oversized limit degrades to the
// default page size instead of erroring or reaching PostgreSQL as
// "no limit".
func TestE2E_FindingsFiltersAndPagination(t *testing.T) {
	slug := newProject(t, "filters")
	key := mintKey(t, slug)

	// Ten findings across two kinds and four severities: the SARIF report
	// contributes one high and one medium (sast), the container scan the
	// remaining eight (sca: two critical, three high, two medium, one low).
	ingestFixture(t, slug, key, "high-medium.sarif.json")
	ingestRaw(t, slug, "trivy", "trivy-alpine-full.json", nil)
	require.Len(t, listFindingsPage(t, slug, ""), 10)

	t.Run("kind selects by scanner family", func(t *testing.T) {
		sast := listFindingsPage(t, slug, "kind=sast")
		require.Len(t, sast, 2)
		for _, f := range sast {
			require.Equal(t, "sast", f.FindingKind)
		}

		sca := listFindingsPage(t, slug, "kind=sca")
		require.Len(t, sca, 8)
		for _, f := range sca {
			require.Equal(t, "sca", f.FindingKind)
		}

		require.Len(t, listFindingsPage(t, slug, "kind=sast%2Csca"), 10,
			"a comma-separated kind list unions")
		require.Empty(t, listFindingsPage(t, slug, "kind=iac"),
			"a kind with no findings selects nothing rather than failing")
	})

	t.Run("severity filters compose with kind", func(t *testing.T) {
		require.Len(t, listFindingsPage(t, slug, "severity=critical"), 2)
		require.Len(t, listFindingsPage(t, slug, "severity=high"), 4)
		require.Len(t, listFindingsPage(t, slug, "severity=high%2Ccritical"), 6)
		require.Len(t, listFindingsPage(t, slug, "severity=high&kind=sast"), 1,
			"separate filters intersect rather than replace one another")
	})

	t.Run("status selects the lifecycle state", func(t *testing.T) {
		require.Len(t, listFindingsPage(t, slug, "status=open"), 10)
		require.Empty(t, listFindingsPage(t, slug, "status=fixed"))
	})

	t.Run("limit and offset bound the page", func(t *testing.T) {
		all, total := findingsPage(t, slug, "")
		require.Len(t, all, 10)
		require.Equal(t, "10", total)

		first, firstTotal := findingsPage(t, slug, "limit=1")
		require.Len(t, first, 1)
		require.Equal(t, all[0].ID, first[0].ID)
		require.Equal(t, "10", firstTotal,
			"the total covers the filtered set, not the page")

		second, _ := findingsPage(t, slug, "limit=1&offset=1")
		require.Len(t, second, 1)
		require.NotEqual(t, first[0].ID, second[0].ID, "offset moves the window")

		require.Len(t, listFindingsPage(t, slug, "limit=3&offset=7"), 3)
		require.Empty(t, listFindingsPage(t, slug, "offset=10"))
		require.Empty(t, listFindingsPage(t, slug, "limit=0"))

		// The total is the size of the filtered set, so it follows the filters
		// rather than the page window: two sast findings, whatever the limit.
		_, sastTotal := findingsPage(t, slug, "kind=sast&limit=1")
		require.Equal(t, "2", sastTotal)
		_, noneTotal := findingsPage(t, slug, "kind=iac")
		require.Equal(t, "0", noneTotal)
	})

	t.Run("malformed and oversized limits fall back to the default page", func(t *testing.T) {
		// A negative limit must never reach PostgreSQL as "no limit": the
		// parser substitutes the default page size, so every one of these
		// returns the full ten rather than the whole table.
		for _, query := range []string{"limit=-1", "limit=abc", "limit=99999999999", "limit=", "offset=-5"} {
			require.Len(t, listFindingsPage(t, slug, query), 10, "query %q", query)
		}
		require.Len(t, listFindingsPage(t, slug, "limit=500"), 10)
	})

	t.Run("closed findings move under status=fixed", func(t *testing.T) {
		// A separate project, so the auto-fix rewrite that closes these
		// findings cannot disturb the counts pinned above.
		fixedSlug := newProject(t, "filters-fixed")
		scope := map[string]any{"branch": "main", "commit_sha": baseSHA}
		ingestRaw(t, fixedSlug, "trivy", "trivy-alpine-scan.json", scope)
		require.Len(t, listFindingsPage(t, fixedSlug, "status=open"), 2)

		ingestRaw(t, fixedSlug, "trivy", "trivy-empty-scan.json", scope)

		require.Empty(t, listFindingsPage(t, fixedSlug, "status=open"))
		require.Len(t, listFindingsPage(t, fixedSlug, "status=fixed"), 2)
		require.Len(t, listFindingsPage(t, fixedSlug, "status=open%2Cfixed"), 2,
			"a comma-separated status list unions")
	})
}
