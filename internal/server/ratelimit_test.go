package server

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func TestRateLimiter_AllowsUnderLimit(t *testing.T) {
	l := NewRateLimiter(10, 20)
	h := l.Middleware(false)(okHandler())

	for range 15 {
		req := httptest.NewRequest("POST", "/api/v1/auth/login", nil)
		req.RemoteAddr = "10.0.0.1:1234"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	}
}

func TestRateLimiter_BlocksOverBurst(t *testing.T) {
	l := NewRateLimiter(1, 3)
	h := l.Middleware(false)(okHandler())

	for range 3 {
		req := httptest.NewRequest("POST", "/api/v1/auth/login", nil)
		req.RemoteAddr = "10.0.0.2:1234"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)
	}
	req := httptest.NewRequest("POST", "/api/v1/auth/login", nil)
	req.RemoteAddr = "10.0.0.2:1234"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusTooManyRequests, w.Code)
	assert.NotEmpty(t, w.Header().Get("Retry-After"), "429 must carry Retry-After")
	assert.Contains(t, w.Body.String(), "rate_limited")
}

func TestRateLimiter_SetsLimitHeaders(t *testing.T) {
	l := NewRateLimiter(10, 20)
	h := l.Middleware(false)(okHandler())

	req := httptest.NewRequest("GET", "/api/v1/projects", nil)
	req.RemoteAddr = "10.0.0.3:1234"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "10", w.Header().Get("X-RateLimit-Limit"))
	remaining, err := strconv.Atoi(w.Header().Get("X-RateLimit-Remaining"))
	require.NoError(t, err)
	assert.GreaterOrEqual(t, remaining, 0)
	assert.LessOrEqual(t, remaining, 20)
}

func TestRateLimiter_PerIPIsolation(t *testing.T) {
	l := NewRateLimiter(1, 1)
	h := l.Middleware(false)(okHandler())

	req := httptest.NewRequest("GET", "/api/v1/projects", nil)
	req.RemoteAddr = "10.0.0.4:1234"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	other := httptest.NewRequest("GET", "/api/v1/projects", nil)
	other.RemoteAddr = "10.0.0.5:1234"
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, other)
	assert.Equal(t, http.StatusOK, w2.Code, "a different IP gets its own bucket")
}

func TestRateLimiter_IdentityTier(t *testing.T) {
	l := NewRateLimiter(1, 1)
	h := l.Middleware(true)(okHandler())

	newAuthed := func() *http.Request {
		req := httptest.NewRequest("GET", "/api/v1/projects", nil)
		req.RemoteAddr = "10.0.0.6:1234"
		return req.WithContext(auth.ContextWithIdentity(req.Context(), &auth.Identity{UserID: "u1"}))
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, newAuthed())
	require.Equal(t, http.StatusOK, w.Code)

	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, newAuthed())
	assert.Equal(t, http.StatusTooManyRequests, w2.Code, "same identity shares one bucket across IPs")
}

func TestRateLimiter_SkipsBearerRequestsWhenIPOnly(t *testing.T) {
	l := NewRateLimiter(1, 1)
	h := l.Middleware(false)(okHandler())

	for range 3 {
		req := httptest.NewRequest("GET", "/api/v1/projects", nil)
		req.RemoteAddr = "10.0.0.7:1234"
		req.Header.Set("Authorization", "Bearer sometoken")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code, "bearer requests are judged post-auth, not against the IP bucket")
	}
}

func TestRateLimiter_ExemptsHealthAndVersion(t *testing.T) {
	l := NewRateLimiter(1, 1)
	h := l.Middleware(false)(okHandler())

	for _, path := range []string{"/api/v1/health", "/api/v1/version"} {
		for range 3 {
			req := httptest.NewRequest("GET", path, nil)
			req.RemoteAddr = "10.0.0.8:1234"
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code, path+" must never be rate limited")
		}
	}
}

func TestRateLimiter_EvictsIdleBuckets(t *testing.T) {
	l := NewRateLimiter(1, 1)
	base := time.Now()
	current := base
	l.now = func() time.Time { return current }
	h := l.Middleware(false)(okHandler())

	limited := func(ip string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "/api/v1/projects", nil)
		req.RemoteAddr = ip + ":1234"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}

	require.Equal(t, http.StatusOK, limited("10.0.0.9").Code)
	require.Equal(t, http.StatusTooManyRequests, limited("10.0.0.9").Code)
	assert.Equal(t, 1, l.BucketCount())

	current = base.Add(rateLimitBucketTTL + time.Second)
	require.Equal(t, http.StatusOK, limited("10.0.1.1").Code)
	assert.Equal(t, 1, l.BucketCount(), "idle buckets must be evicted")
	assert.Equal(t, http.StatusOK, limited("10.0.0.9").Code, "evicted IP gets a fresh bucket")
}
