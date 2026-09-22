package server

import (
	"math"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/xMinhx/specht/internal/auth"
)

// rateLimitBucketTTL bounds memory: per-key token buckets idle longer than
// this are evicted on the next request. In-memory buckets reset on restart,
// which is acceptable for single-instance self-host deployments (no Redis).
const rateLimitBucketTTL = 3 * time.Minute

// rateLimitExempt are paths that must never be rate limited: orchestration
// health checks (Docker HEALTHCHECK, compose depends_on) and the version
// endpoint used by deployment tooling.
var rateLimitExempt = map[string]bool{
	"/api/v1/health":  true,
	"/api/v1/version": true,
}

// RateLimitConfig tunes the two limiter tiers. The IP tier guards
// unauthenticated entry points (register, login); the auth tier gives
// authenticated callers a generous budget.
type RateLimitConfig struct {
	Enabled   bool
	RPS       int
	Burst     int
	AuthRPS   int
	AuthBurst int
}

type rateLimitVisitor struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// RateLimiter is a per-key token-bucket limiter. A zero value is unusable;
// build one with NewRateLimiter. It is safe for concurrent use.
type RateLimiter struct {
	mu        sync.Mutex
	visitors  map[string]*rateLimitVisitor
	rps       int
	burst     int
	lastSweep time.Time
	now       func() time.Time
}

// NewRateLimiter builds a limiter allowing rps requests per second with the
// given burst per key. Non-positive values fall back to 1.
func NewRateLimiter(rps, burst int) *RateLimiter {
	if rps <= 0 {
		rps = 1
	}
	if burst <= 0 {
		burst = 1
	}
	return &RateLimiter{
		visitors: make(map[string]*rateLimitVisitor),
		rps:      rps,
		burst:    burst,
		now:      time.Now,
	}
}

// BucketCount reports the number of live per-key buckets. Tests use it to
// assert eviction; production code does not need it.
func (l *RateLimiter) BucketCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.visitors)
}

func (l *RateLimiter) limiterFor(key string, now time.Time) *rate.Limiter {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.lastSweep) >= rateLimitBucketTTL {
		for k, v := range l.visitors {
			if now.Sub(v.lastSeen) > rateLimitBucketTTL {
				delete(l.visitors, k)
			}
		}
		l.lastSweep = now
	}
	v, ok := l.visitors[key]
	if !ok {
		v = &rateLimitVisitor{limiter: rate.NewLimiter(rate.Limit(l.rps), l.burst)}
		l.visitors[key] = v
	}
	v.lastSeen = now
	return v.limiter
}

// Middleware enforces the bucket for each request. When useIdentity is set,
// an authenticated identity selects the key (one budget per caller,
// regardless of IP); otherwise the client IP selects the key, except that
// requests carrying an Authorization header pass through — they are judged
// by the post-auth instance, so one request never spends two budgets.
func (l *RateLimiter) Middleware(useIdentity bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if rateLimitExempt[r.URL.Path] {
				next.ServeHTTP(w, r)
				return
			}
			key, ok := l.rateLimitKey(r, useIdentity)
			if !ok {
				next.ServeHTTP(w, r)
				return
			}
			limiter := l.limiterFor(key, l.now())
			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(l.rps))
			if limiter.Allow() {
				remaining := int(math.Floor(limiter.Tokens()))
				if remaining < 0 {
					remaining = 0
				}
				w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
				next.ServeHTTP(w, r)
				return
			}
			writeRateLimited(w, limiter)
		})
	}
}

// rateLimitKey resolves the bucket key for a request. It reports false when
// the request passes through unlimited (authenticated traffic on an
// anonymous-scoped route).
func (l *RateLimiter) rateLimitKey(r *http.Request, useIdentity bool) (string, bool) {
	if useIdentity {
		if ident := auth.ContextIdentity(r.Context()); ident != nil {
			return "user:" + ident.UserID, true
		}
	} else if r.Header.Get("Authorization") != "" {
		return "", false
	}
	return "ip:" + clientHost(r), true
}

// writeRateLimited emits the 429 response with a Retry-After hint derived
// from the limiter's next reservation.
func writeRateLimited(w http.ResponseWriter, limiter *rate.Limiter) {
	reservation := limiter.Reserve()
	delay := reservation.Delay()
	reservation.Cancel()
	secs := int(math.Ceil(delay.Seconds()))
	if secs < 1 {
		secs = 1
	}
	w.Header().Set("X-RateLimit-Remaining", "0")
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	respondError(w, http.StatusTooManyRequests, "rate_limited", "rate limit exceeded, retry later")
}

// clientHost returns the remote host without port. realIPMiddleware (which
// runs before this middleware) has already resolved trusted-proxy headers,
// so RemoteAddr is the best available client address here.
func clientHost(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
