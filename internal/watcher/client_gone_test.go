package watcher

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestQueryBatchSkipsAnAdvisoryTheFeedNoLongerHas(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/querybatch":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"GHSA-gone"},{"id":"GHSA-live"}]}]}`))
		case r.URL.Path == "/vulns/GHSA-gone":
			http.NotFound(w, r)
		case r.URL.Path == "/vulns/GHSA-live":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"GHSA-live","summary":"still here"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := NewHTTPClient(HTTPClientConfig{
		Endpoint:     server.URL + "/querybatch",
		VulnEndpoint: server.URL + "/vulns/{id}",
		HTTP:         server.Client(),
	})
	results, err := client.QueryBatch(context.Background(), []Query{{Package: QueryPackage{Ecosystem: "npm", Name: "pkg"}}})
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.Len(t, results[0].Advisories, 1)
	require.Equal(t, "GHSA-live", results[0].Advisories[0].ID)
}
