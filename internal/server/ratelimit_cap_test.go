package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func capTestRequest(h http.Handler, ip string) int {
	req := httptest.NewRequest("GET", "/api/v1/projects", nil)
	req.RemoteAddr = ip + ":1234"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w.Code
}

func TestRateLimiter_BucketCountNeverExceedsCap(t *testing.T) {
	l := NewLoginRateLimiter(5, 5)
	fixed := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	l.now = func() time.Time { return fixed }

	const flood = 3 * maxLiveBuckets
	for i := range flood {
		l.limiterFor(fmt.Sprintf("ip:flood-%d", i), fixed)
		if i%10_000 == 0 {
			require.LessOrEqual(t, l.BucketCount(), maxLiveBuckets, "after %d keys", i)
		}
	}
	assert.Equal(t, maxLiveBuckets, l.BucketCount(), "the map stops at the cap")
}

func TestRateLimiter_KeyWithBucketKeepsItWhenFull(t *testing.T) {
	l := NewRateLimiter(1, 3)
	l.store.max = 10
	fixed := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	l.now = func() time.Time { return fixed }
	h := l.Middleware(false)(okHandler())

	// The victim holds a bucket and spends one of its three tokens.
	require.Equal(t, http.StatusOK, capTestRequest(h, "10.1.0.1"))
	victim := l.limiterFor("ip:10.1.0.1", fixed)

	for i := range 200 {
		capTestRequest(h, fmt.Sprintf("10.2.0.%d", i))
	}
	assert.LessOrEqual(t, l.BucketCount(), 10)
	assert.Same(t, victim, l.limiterFor("ip:10.1.0.1", fixed), "a flood never replaces a live bucket")
	assert.Equal(t, http.StatusOK, capTestRequest(h, "10.1.0.1"))
	assert.Equal(t, http.StatusOK, capTestRequest(h, "10.1.0.1"), "the victim still has its own remaining burst")
}

func TestRateLimiter_NewKeysShareOneOverflowBucketWhenFull(t *testing.T) {
	l := NewRateLimiter(1, 3)
	l.store.max = 4
	fixed := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	l.now = func() time.Time { return fixed }
	h := l.Middleware(false)(okHandler())

	for i := range 4 {
		require.Equal(t, http.StatusOK, capTestRequest(h, fmt.Sprintf("10.3.0.%d", i)))
	}
	allowed := 0
	for i := range 50 {
		if capTestRequest(h, fmt.Sprintf("10.4.0.%d", i)) == http.StatusOK {
			allowed++
		}
	}
	assert.Equal(t, 3, allowed, "unseen keys draw on one shared burst of 3")
	assert.Equal(t, 4, l.BucketCount())
}

func TestRateLimiter_FullMapSweepsExpiredEntriesBeforeOverflowing(t *testing.T) {
	l := NewRateLimiter(1, 1)
	l.store.max = 4
	current := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	l.now = func() time.Time { return current }
	h := l.Middleware(false)(okHandler())

	for i := range 4 {
		require.Equal(t, http.StatusOK, capTestRequest(h, fmt.Sprintf("10.5.0.%d", i)))
	}
	// Just past the TTL the periodic sweep has already run once, so only the
	// full-map sweep can free room for the next key.
	current = current.Add(rateLimitBucketTTL)
	l.limiterFor("ip:10.5.0.0", current)
	current = current.Add(time.Second)

	require.Equal(t, http.StatusOK, capTestRequest(h, "10.6.0.1"))
	require.Equal(t, http.StatusOK, capTestRequest(h, "10.6.0.2"), "expired entries made room for their own buckets")
	require.Equal(t, http.StatusOK, capTestRequest(h, "10.6.0.3"))
}
