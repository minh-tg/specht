package client

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// An https API that answers 302 to http:// on the same host must not get the
// bearer key sent in clear on the second hop. Both test servers listen on
// 127.0.0.1 with different ports, so the redirect changes scheme and host.
func TestClient_DoesNotFollowARedirectToPlainHTTP(t *testing.T) {
	var plainHits atomic.Int32
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		plainHits.Add(1)
		assert.Empty(t, r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"u","email":"a@b.c","role":"user"}`))
	}))
	defer plain.Close()
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+r.URL.Path, http.StatusFound)
	}))
	defer tlsSrv.Close()

	c := New(tlsSrv.URL, WithHTTPClient(tlsSrv.Client()), WithToken("secret-key"))
	_, err := c.Me()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refusing a redirect")
	assert.Zero(t, plainHits.Load(), "the plain http server must not be contacted")
}

func TestClient_FollowsASameOriginRedirect(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/me" {
			http.Redirect(w, r, "/moved", http.StatusFound)
			return
		}
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"u","email":"a@b.c","role":"user"}`))
	}))
	defer srv.Close()

	c := New(srv.URL, WithToken("secret-key"))
	_, err := c.Me()
	require.NoError(t, err)
	assert.Equal(t, "Bearer secret-key", gotAuth)
}

func TestRefuseCrossOriginRedirect(t *testing.T) {
	mk := func(u string) *http.Request {
		r, err := http.NewRequest(http.MethodGet, u, nil)
		require.NoError(t, err)
		return r
	}
	via := []*http.Request{mk("https://api.example.com/a")}
	assert.NoError(t, RefuseCrossOriginRedirect(mk("https://api.example.com/b"), via))
	assert.Error(t, RefuseCrossOriginRedirect(mk("http://api.example.com/b"), via))
	assert.Error(t, RefuseCrossOriginRedirect(mk("https://evil.example.com/b"), via))
	assert.Error(t, RefuseCrossOriginRedirect(mk("https://api.example.com:8443/b"), via))
}
