package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/auth"
)

func rateLimitHit(h http.Handler, ident *auth.Identity, header string) int {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/reports", nil)
	req.RemoteAddr = "10.9.9.9:1234"
	if header != "" {
		req.Header.Set("Authorization", header)
	}
	if ident != nil {
		req = req.WithContext(auth.ContextWithIdentity(req.Context(), ident))
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w.Code
}

// fakeKeyAuth authenticates every token as a live key of the given creator and
// project.
func fakeKeyAuth(creator, project string) auth.Authenticator {
	return auth.NewAPIKeyAuthenticator(func(_ context.Context, keyHash string) (string, string, []string, time.Time, error) {
		return creator, project, []string{auth.ScopeIngest}, time.Time{}, nil
	})
}

// Two keys that share a creator, and the creator's own session, each get their
// own post-auth budget.
func TestRateLimit_PostAuthBucketIsPerKeyAndPerSession(t *testing.T) {
	h := NewRateLimiter(1, 2).Middleware(true)(okHandler())
	keyA := &auth.Identity{UserID: "admin-1", ProjectID: "project-a", KeyHash: "hash-a", IsAPIKey: true, Scopes: []string{auth.ScopeIngest}}
	keyB := &auth.Identity{UserID: "admin-1", ProjectID: "project-b", KeyHash: "hash-b", IsAPIKey: true, Scopes: []string{auth.ScopeIngest}}
	session := &auth.Identity{UserID: "admin-1", Role: auth.RoleAdmin}

	require.Equal(t, http.StatusOK, rateLimitHit(h, keyA, ""))
	require.Equal(t, http.StatusOK, rateLimitHit(h, keyA, ""))
	require.Equal(t, http.StatusTooManyRequests, rateLimitHit(h, keyA, ""), "key A spent its own budget")

	require.Equal(t, http.StatusOK, rateLimitHit(h, keyB, ""), "key B has its own budget")
	require.Equal(t, http.StatusOK, rateLimitHit(h, session, ""), "the creator's session has its own budget")
}

// The authenticator stamps the key's hash on the identity, which is what the
// bucket is keyed by.
func TestAPIKeyAuthenticator_IdentityCarriesKeyHash(t *testing.T) {
	a := fakeKeyAuth("admin-1", "project-a")
	one, err := a.Authenticate(context.Background(), "vuln_one")
	require.NoError(t, err)
	two, err := a.Authenticate(context.Background(), "vuln_two")
	require.NoError(t, err)
	require.NotEmpty(t, one.KeyHash)
	require.NotEqual(t, one.KeyHash, two.KeyHash)
}

// A request with a junk bearer is judged by the IP bucket after authentication
// fails, so a client cannot dodge the limiter by sending any Authorization
// header.
func TestRateLimit_FailedBearerCountsAgainstIPBucket(t *testing.T) {
	limiter := NewRateLimiter(1, 2)
	rejecting := auth.NewAPIKeyAuthenticator(func(context.Context, string) (string, string, []string, time.Time, error) {
		return "", "", nil, time.Time{}, context.Canceled
	})
	h := limiter.Middleware(false)(AuthMiddlewareLimited(limiter, rejecting)(okHandler()))

	require.Equal(t, http.StatusUnauthorized, rateLimitHit(h, nil, "Bearer vuln_not-a-real-key"))
	require.Equal(t, http.StatusUnauthorized, rateLimitHit(h, nil, "Bearer vuln_not-a-real-key"))
	require.Equal(t, http.StatusTooManyRequests, rateLimitHit(h, nil, "Bearer vuln_not-a-real-key"),
		"the third junk bearer from one address is limited")
	require.Equal(t, http.StatusTooManyRequests, rateLimitHit(h, nil, "Basic abc"),
		"a non-bearer scheme spends the same bucket")
}

// A request that authenticates does not spend the IP bucket, so CI behind a
// shared address is not limited by its own successful traffic.
func TestRateLimit_SuccessfulBearerLeavesIPBucketAlone(t *testing.T) {
	limiter := NewRateLimiter(1, 2)
	h := limiter.Middleware(false)(AuthMiddlewareLimited(limiter, fakeKeyAuth("admin-1", "project-a"))(okHandler()))
	for range 10 {
		require.Equal(t, http.StatusOK, rateLimitHit(h, nil, "Bearer vuln_good"))
	}
	// The anonymous bucket is still full.
	require.Equal(t, http.StatusUnauthorized, rateLimitHit(h, nil, "Basic abc"))
}
