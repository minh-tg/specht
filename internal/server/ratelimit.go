package server

import (
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type ipLimiter struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

type RateLimiterConfig struct {
	Enabled bool
	RPS     int
	Burst   int
}

func NewRateLimiterConfig() RateLimiterConfig {
	return RateLimiterConfig{
		Enabled: false,
		RPS:     10,
		Burst:   20,
	}
}

type RateLimiter struct {
	mu      sync.Mutex
	clients map[string]*ipLimiter
	ttl     time.Duration
	rps     rate.Limit
	burst   int
	enabled bool
}

func NewRateLimiter(cfg RateLimiterConfig) *RateLimiter {
	return &RateLimiter{
		clients: make(map[string]*ipLimiter),
		ttl:     time.Minute,
		rps:     rate.Limit(cfg.RPS),
		burst:   cfg.Burst,
		enabled: cfg.Enabled,
	}
}

func (rl *RateLimiter) getLimiter(ip string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	entry, ok := rl.clients[ip]
	if !ok {
		limiter := rate.NewLimiter(rl.rps, rl.burst)
		rl.clients[ip] = &ipLimiter{limiter: limiter, lastSeen: time.Now()}
		return limiter
	}
	entry.lastSeen = time.Now()
	return entry.limiter
}

func (rl *RateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	for ip, entry := range rl.clients {
		if time.Since(entry.lastSeen) > rl.ttl {
			delete(rl.clients, ip)
		}
	}
}

func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	if !rl.enabled {
		return next
	}

	go func() {
		ticker := time.NewTicker(rl.ttl)
		defer ticker.Stop()
		for range ticker.C {
			rl.cleanup()
		}
	}()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}

		limiter := rl.getLimiter(host)
		if !limiter.Allow() {
			w.Header().Set("Retry-After", "1")
			w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", int(rl.rps)))
			http.Error(w, `{"error":{"code":"rate_limit_exceeded","message":"too many requests"}}`, http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}
