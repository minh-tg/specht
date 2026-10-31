package intel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// feedInternalTarget stands in for a host on the server's private network. It
// listens on loopback, which the default client admits for a loopback feed
// URL, so only the redirect block keeps the client away from it.
func feedInternalTarget(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// feedRedirector answers every request with a redirect to the given address.
func feedRedirector(t *testing.T, to string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, to, http.StatusFound)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// The providers have no Client in production (buildIntelStore), so these
// tests use the default client.
func TestEPSSProviderRefusesRedirect(t *testing.T) {
	internal, hits := feedInternalTarget(t)
	feed := feedRedirector(t, internal.URL+"/latest/meta-data/iam/security-credentials/")
	p := &EPSSProvider{BaseURL: feed.URL}
	_, err := p.Fetch(context.Background(), []string{"CVE-2024-3094"})
	require.Error(t, err)
	assert.Zero(t, hits.Load(), "EPSS client followed the redirect")
}

func TestKEVProviderRefusesRedirect(t *testing.T) {
	internal, hits := feedInternalTarget(t)
	feed := feedRedirector(t, internal.URL+"/internal/admin")
	p := &KEVProvider{CatalogURL: feed.URL}
	_, err := p.Fetch(context.Background(), []string{"CVE-2024-3094"})
	require.Error(t, err)
	assert.Zero(t, hits.Load(), "KEV client followed the redirect")
}

func TestEPSSProviderRefusesPrivateFeed(t *testing.T) {
	for _, base := range []string{"http://169.254.169.254/epss", "http://10.0.0.5:8080/epss", "http://[fd00::1]/epss"} {
		p := &EPSSProvider{BaseURL: base}
		_, err := p.Fetch(context.Background(), []string{"CVE-2024-3094"})
		require.Error(t, err, base)
		assert.Contains(t, err.Error(), "non-public address", base)
	}
}

func TestKEVProviderRefusesPrivateFeed(t *testing.T) {
	for _, catalog := range []string{"http://169.254.169.254/kev.json", "http://10.0.0.5:8080/kev.json", "http://[fd00::1]/kev.json"} {
		p := &KEVProvider{CatalogURL: catalog}
		_, err := p.Fetch(context.Background(), []string{"CVE-2024-3094"})
		require.Error(t, err, catalog)
		assert.Contains(t, err.Error(), "non-public address", catalog)
	}
}

func TestProvidersReachALoopbackFeedWithTheDefaultClient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, `{"status":"OK","data":[{"cve":"CVE-2024-3094","epss":"0.5","percentile":"0.9","date":"2026-01-01"}],"vulnerabilities":[{"cveID":"CVE-2024-3094"}]}`)
	}))
	t.Cleanup(srv.Close)

	got, err := (&EPSSProvider{BaseURL: srv.URL}).Fetch(context.Background(), []string{"CVE-2024-3094"})
	require.NoError(t, err)
	assert.Contains(t, got, "CVE-2024-3094")

	got, err = (&KEVProvider{CatalogURL: srv.URL}).Fetch(context.Background(), []string{"CVE-2024-3094"})
	require.NoError(t, err)
	assert.Contains(t, got, "CVE-2024-3094")
}
