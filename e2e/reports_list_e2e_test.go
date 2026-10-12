//go:build e2e

package e2e

import (
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

type reportListRow struct {
	ID        string  `json:"id"`
	Status    string  `json:"status"`
	Branch    *string `json:"branch"`
	CommitSha *string `json:"commit_sha"`
}

// getReports reads the report list with optional headers and returns the
// raw status, the ETag and the body so a test can exercise 304 handling.
func getReports(t *testing.T, slug, query, ifNoneMatch string) (int, string, []byte) {
	t.Helper()
	path := baseURL + "/api/v1/projects/" + slug + "/reports"
	if query != "" {
		path += "?" + query
	}
	req, err := http.NewRequest(http.MethodGet, path, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	if ifNoneMatch != "" {
		req.Header.Set("If-None-Match", ifNoneMatch)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, resp.Header.Get("ETag"), body
}

// TestE2E_ReportListBranchCommitAndETag covers how a client waits for the
// next scan: it asks for the newest report on a branch, and a poll that finds
// nothing new costs a 304 with no body.
func TestE2E_ReportListBranchCommitAndETag(t *testing.T) {
	slug := newProject(t, "reports-wait")
	key := mintKey(t, slug)

	post := func(branch, commit string) ingestResponse {
		return request[ingestResponse](t, http.MethodPost, "/api/v1/reports", key,
			ingestBodyWith(t, slug, "high-medium.sarif.json", map[string]any{"branch": branch, "commit_sha": commit}),
			http.StatusCreated)
	}
	onMain := post("main", "aaaaaaa1111")
	onFeature := post("feature/refund-retry", "bbbbbbb2222")

	list := func(query string) []reportListRow {
		t.Helper()
		return request[[]reportListRow](t, http.MethodGet, "/api/v1/projects/"+slug+"/reports?"+query, adminToken, nil, http.StatusOK)
	}

	t.Run("newest report on a branch", func(t *testing.T) {
		got := list("branch=feature/refund-retry&limit=1")
		require.Len(t, got, 1)
		require.Equal(t, onFeature.ReportID, got[0].ID)
		require.Equal(t, "completed", got[0].Status)
		require.Len(t, list("branch=main"), 1)
		require.Equal(t, onMain.ReportID, list("branch=main")[0].ID)
		require.Empty(t, list("branch=no-such-branch"))
	})

	t.Run("exact commit", func(t *testing.T) {
		got := list("commit=bbbbbbb2222")
		require.Len(t, got, 1)
		require.Equal(t, onFeature.ReportID, got[0].ID)
		require.Empty(t, list("commit=ccccccc3333"))
	})

	t.Run("malformed filters are refused", func(t *testing.T) {
		status, _, raw := getReports(t, slug, "commit=zzz", "")
		require.Equal(t, http.StatusBadRequest, status, string(raw))
		require.Equal(t, "invalid_commit", errorCode(t, raw))
	})

	t.Run("an unchanged list answers 304", func(t *testing.T) {
		status, etag, _ := getReports(t, slug, "branch=main&limit=1", "")
		require.Equal(t, http.StatusOK, status)
		require.NotEmpty(t, etag)

		status, again, body := getReports(t, slug, "branch=main&limit=1", etag)
		require.Equal(t, http.StatusNotModified, status)
		require.Equal(t, etag, again)
		require.Empty(t, body)

		post("main", "ddddddd4444")
		status, changed, _ := getReports(t, slug, "branch=main&limit=1", etag)
		require.Equal(t, http.StatusOK, status, "a new report on the branch invalidates the tag")
		require.NotEqual(t, etag, changed)
	})
}
