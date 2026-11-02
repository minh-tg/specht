package watcher

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEndpointVuln_EscapesTheID(t *testing.T) {
	c := NewHTTPClient(HTTPClientConfig{VulnEndpoint: "https://osv.example/v1/vulns/{id}"})
	assert.Equal(t, "https://osv.example/v1/vulns/GHSA-aaaa", c.endpointVuln("GHSA-aaaa"))
	assert.Equal(t, "https://osv.example/v1/vulns/openSUSE-SU-2024:0001-1", c.endpointVuln("openSUSE-SU-2024:0001-1"))
	assert.Equal(t, "https://osv.example/v1/vulns/a%2F..%2Fb%3Fx=1", c.endpointVuln("a/../b?x=1"))
}

func TestVulnIDPattern(t *testing.T) {
	for _, ok := range []string{"GHSA-xxxx-xxxx-xxxx", "CVE-2024-12345", "GO-2024-1234", "RUSTSEC-2024-0001", "openSUSE-SU-2024:0001-1", "DSA-5000-1", "PYSEC-2024-1"} {
		assert.True(t, vulnIDPattern.MatchString(ok), ok)
	}
	for _, bad := range []string{"", "..", "../../admin?x=", "a/b", "a b", "GHSA-a\nb", "GHSA-a\x00", "-lead", ".lead", "a?b", "a#b", "a%2Fb", "é"} {
		assert.False(t, vulnIDPattern.MatchString(bad), bad)
	}
	long := make([]byte, 129)
	for i := range long {
		long[i] = 'a'
	}
	assert.False(t, vulnIDPattern.MatchString(string(long)))
}

// An advisory id that is not a valid id must not reach the vuln endpoint and
// must not stop the other advisories of the poll.
func TestQueryBatch_SkipsAnInvalidAdvisoryID(t *testing.T) {
	var mu sync.Mutex
	var gotURIs []string
	ids := []string{"GHSA-good", "../../admin?x=", "GHSA-a\nb"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			vulns := []map[string]any{}
			for _, id := range ids {
				vulns = append(vulns, map[string]any{"id": id})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"results": []map[string]any{{"vulns": vulns}}})
			return
		}
		mu.Lock()
		gotURIs = append(gotURIs, r.RequestURI)
		mu.Unlock()
		_ = json.NewEncoder(w).Encode(cannedAdvisory("GHSA-good", "2024-01-01T00:00:00Z"))
	}))
	defer srv.Close()

	c := NewHTTPClient(HTTPClientConfig{Endpoint: srv.URL + "/v1/querybatch", VulnEndpoint: srv.URL + "/v1/vulns/{id}", HTTP: srv.Client()})
	results, err := c.QueryBatch(context.Background(), []Query{queryFor("lodash")})
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.Len(t, results[0].Advisories, 1)
	assert.Equal(t, []string{"/v1/vulns/GHSA-good"}, gotURIs)
}
