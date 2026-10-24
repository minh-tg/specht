package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPublicRateLimitsCannotBeSkippedWithAuthorizationHeader(t *testing.T) {
	for _, path := range []string{"/api/v1/ready", "/api/v1/capabilities", "/api/v1/auth/sso/login", "/not-registered"} {
		for _, header := range []string{"", "Bearer arbitrary"} {
			t.Run(path+header, func(t *testing.T) {
				router := NewRouter(RouterConfig{Usecases: &mockUsecases{setupRequiredFn: func(context.Context) (bool, error) { return false, nil }}, OIDCEnabled: true, OIDC: testOIDC(t), RateLimit: RateLimitConfig{Enabled: true, RPS: 1, Burst: 1}})
				for i := 0; i < 3; i++ {
					req := httptest.NewRequest(http.MethodGet, path, nil)
					req.Header.Set("Authorization", header)
					w := httptest.NewRecorder()
					router.ServeHTTP(w, req)
					if i == 0 {
						require.NotEqual(t, http.StatusTooManyRequests, w.Code)
					} else {
						require.Equal(t, http.StatusTooManyRequests, w.Code)
					}
				}
			})
		}
	}
}
