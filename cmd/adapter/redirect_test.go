package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The adapter's API client must not follow a redirect from https to a plain
// http server, where it would resend the bearer key in clear.
func TestAdapterHTTPClientRefusesARedirectToPlainHTTP(t *testing.T) {
	var plainHits atomic.Int32
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		plainHits.Add(1)
		assert.Empty(t, r.Header.Get("Authorization"))
	}))
	defer plain.Close()
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+r.URL.Path, http.StatusFound)
	}))
	defer tlsSrv.Close()

	hc := newAdapterHTTPClient(tlsSrv.Client(), func(context.Context, time.Duration) {})
	req, err := http.NewRequest(http.MethodGet, tlsSrv.URL+"/api/v1/me", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer secret-key")
	resp, err := hc.Do(req)
	if resp != nil {
		require.NoError(t, resp.Body.Close())
	}
	require.Error(t, err)
	assert.Zero(t, plainHits.Load())
}
