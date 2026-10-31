package watcher

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/netutil"
)

const internalBanner = "INTERNAL-ONLY root:x:0:0 db_password=hunter2"

// internalService stands in for a host on the server's private network. It
// records whether the client reached it and answers with a body that must
// never show up in an error, a log line or stored evidence. It listens on
// loopback, which the default client admits for a loopback endpoint, so only
// the redirect block keeps the client away from it.
func internalService(t *testing.T, status int, body string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func TestOSVClientRefusesQueryBatchRedirect(t *testing.T) {
	internal, hits := internalService(t, http.StatusInternalServerError, internalBanner)
	osv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, internal.URL+"/admin/export", http.StatusTemporaryRedirect)
	}))
	t.Cleanup(osv.Close)

	c := NewHTTPClient(HTTPClientConfig{Endpoint: osv.URL, VulnEndpoint: osv.URL + "/v1/vulns/{id}"})
	_, err := c.QueryBatch(context.Background(), []Query{queryFor("lodash")})
	require.Error(t, err)
	assert.Zero(t, hits.Load(), "querybatch followed the redirect")
	assert.NotContains(t, err.Error(), internalBanner)
}

func TestOSVClientRefusesVulnRedirect(t *testing.T) {
	internal, hits := internalService(t, http.StatusOK, `{"id":"GHSA-x","summary":"`+internalBanner+`"}`)
	osv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			_, _ = w.Write(querybatchResponse([]map[string]any{{"id": "GHSA-x"}}))
			return
		}
		http.Redirect(w, r, internal.URL+"/secret", http.StatusFound)
	}))
	t.Cleanup(osv.Close)

	c := NewHTTPClient(HTTPClientConfig{Endpoint: osv.URL, VulnEndpoint: osv.URL + "/v1/vulns/{id}"})
	res, err := c.QueryBatch(context.Background(), []Query{queryFor("lodash")})
	require.Error(t, err)
	assert.Nil(t, res)
	assert.Zero(t, hits.Load(), "full-record fetch followed the redirect")
	assert.NotContains(t, err.Error(), internalBanner)
}

func TestOSVClientRefusesPrivateQueryBatchEndpoint(t *testing.T) {
	for _, endpoint := range []string{
		"http://169.254.169.254/v1/querybatch",
		"http://10.0.0.5:8080/v1/querybatch",
		"http://[fd00::1]/v1/querybatch",
	} {
		c := NewHTTPClient(HTTPClientConfig{Endpoint: endpoint})
		_, err := c.QueryBatch(context.Background(), []Query{queryFor("lodash")})
		require.Error(t, err, endpoint)
		assert.Contains(t, err.Error(), "non-public address", endpoint)
	}
}

func TestOSVClientRefusesPrivateVulnEndpoint(t *testing.T) {
	osv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(querybatchResponse([]map[string]any{{"id": "GHSA-x"}}))
	}))
	t.Cleanup(osv.Close)

	c := NewHTTPClient(HTTPClientConfig{Endpoint: osv.URL, VulnEndpoint: "http://169.254.169.254/v1/vulns/{id}"})
	_, err := c.QueryBatch(context.Background(), []Query{queryFor("lodash")})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "non-public address")
}

func TestHTTPErrorOmitsUpstreamBody(t *testing.T) {
	want := "osv querybatch: http 500 Internal Server Error"
	failing := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(internalBanner))
	}

	t.Run("querybatch", func(t *testing.T) {
		osv := httptest.NewServer(http.HandlerFunc(failing))
		t.Cleanup(osv.Close)
		c := NewHTTPClient(HTTPClientConfig{Endpoint: osv.URL})
		_, err := c.QueryBatch(context.Background(), []Query{queryFor("lodash")})
		require.Error(t, err)
		assert.Equal(t, want, err.Error())
	})
	t.Run("full record", func(t *testing.T) {
		osv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost {
				_, _ = w.Write(querybatchResponse([]map[string]any{{"id": "GHSA-x"}}))
				return
			}
			failing(w, r)
		}))
		t.Cleanup(osv.Close)
		c := NewHTTPClient(HTTPClientConfig{Endpoint: osv.URL, VulnEndpoint: osv.URL + "/v1/vulns/{id}"})
		_, err := c.QueryBatch(context.Background(), []Query{queryFor("lodash")})
		require.Error(t, err)
		assert.Equal(t, want, err.Error())
	})
}

// paddedJSON returns a valid JSON document of exactly size bytes.
func paddedJSON(prefix string, size int) []byte {
	pad := size - len(prefix)
	return append([]byte(prefix), bytes.Repeat([]byte(" "), pad)...)
}

func TestOSVClientFailsOnOversizeQueryBatchBody(t *testing.T) {
	osv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(paddedJSON(`{"results":[{}]}`, maxResponseBytes+1))
	}))
	t.Cleanup(osv.Close)

	c := NewHTTPClient(HTTPClientConfig{Endpoint: osv.URL})
	_, err := c.QueryBatch(context.Background(), []Query{queryFor("lodash")})
	require.Error(t, err)
	assert.ErrorIs(t, err, netutil.ErrBodyTooLarge)
	assert.NotErrorIs(t, err, ErrMalformedResponse)
	assert.False(t, IsRetryable(err), "an oversize answer is deterministic")
}

func TestOSVClientAcceptsQueryBatchBodyAtTheCap(t *testing.T) {
	osv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(paddedJSON(`{"results":[{}]}`, maxResponseBytes))
	}))
	t.Cleanup(osv.Close)

	c := NewHTTPClient(HTTPClientConfig{Endpoint: osv.URL})
	res, err := c.QueryBatch(context.Background(), []Query{queryFor("lodash")})
	require.NoError(t, err)
	assert.Len(t, res, 1)
}

func TestOSVClientFailsOnOversizeFullRecord(t *testing.T) {
	osv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			_, _ = w.Write(querybatchResponse([]map[string]any{{"id": "GHSA-x"}}))
			return
		}
		_, _ = w.Write(paddedJSON(`{"id":"GHSA-x"}`, maxResponseBytes+1))
	}))
	t.Cleanup(osv.Close)

	c := NewHTTPClient(HTTPClientConfig{Endpoint: osv.URL, VulnEndpoint: osv.URL + "/v1/vulns/{id}"})
	res, err := c.QueryBatch(context.Background(), []Query{queryFor("lodash")})
	require.Error(t, err)
	assert.Nil(t, res, "a truncated record must not be stored as evidence")
	assert.ErrorIs(t, err, netutil.ErrBodyTooLarge)
	assert.False(t, IsRetryable(err))
}
