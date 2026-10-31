package cvedetail

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProvidersRefuseNonPublicAddresses(t *testing.T) {
	for _, base := range []string{
		"https://169.254.169.254/rest/json/cves/2.0",
		"https://10.0.0.5:8443/rest/json/cves/2.0",
		"https://[fd00::1]/rest/json/cves/2.0",
	} {
		p := &NVD{BaseURL: base, Client: NewHTTPClient(2*time.Second, false)}
		_, err := p.Lookup(context.Background(), testCVE)
		require.Error(t, err, base)
		assert.Contains(t, err.Error(), "non-public address", base)
	}
}

// Both client variants must refuse a redirect, including the one an operator
// opts into for a private mirror.
func TestNewHTTPClientRefusesRedirects(t *testing.T) {
	var targetHits int
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { targetHits++ }))
	t.Cleanup(target.Close)
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	t.Cleanup(front.Close)

	for name, allowPrivate := range map[string]bool{"default": false, "private mirror allowed": true} {
		t.Run(name, func(t *testing.T) {
			client := NewHTTPClient(2*time.Second, allowPrivate)
			resp, err := client.Get(front.URL)
			if resp != nil {
				_ = resp.Body.Close()
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), "redirects are not allowed")
			assert.Zero(t, targetHits)
		})
	}
}
