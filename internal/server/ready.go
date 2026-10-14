package server

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

const (
	// readyTimeout bounds one dependency check, so a database that hangs
	// cannot hang the probe.
	readyTimeout = 2 * time.Second
	// readyCacheTTL is how long an answer is reused. The endpoint is public,
	// so without it anyone could turn the probe into steady database load.
	readyCacheTTL = time.Second
)

// readiness answers "can this instance serve requests right now". It differs
// from the liveness probe, which only says the process is up: readiness fails
// while the database is unreachable.
type readiness struct {
	check   func(ctx context.Context) error
	timeout time.Duration
	ttl     time.Duration
	now     func() time.Time

	mu        sync.Mutex
	checkedAt time.Time
	lastErr   error
	known     bool
}

func newReadiness(check func(ctx context.Context) error) *readiness {
	return &readiness{check: check, timeout: readyTimeout, ttl: readyCacheTTL, now: time.Now}
}

// result runs the check unless a recent answer exists. The lock is held across
// the check so concurrent probes share one database round trip.
func (rd *readiness) result(ctx context.Context) error {
	rd.mu.Lock()
	defer rd.mu.Unlock()
	if rd.known && rd.now().Sub(rd.checkedAt) < rd.ttl {
		return rd.lastErr
	}
	checkCtx, cancel := context.WithTimeout(ctx, rd.timeout)
	defer cancel()
	err := rd.check(checkCtx)
	if rd.known && (err == nil) != (rd.lastErr == nil) {
		// Log the change, not every probe.
		if err != nil {
			slog.Warn("readiness check failed", "error", err)
		} else {
			slog.Info("readiness check recovered")
		}
	} else if !rd.known && err != nil {
		slog.Warn("readiness check failed", "error", err)
	}
	rd.lastErr, rd.checkedAt, rd.known = err, rd.now(), true
	return err
}

// handler answers 200 when ready and 503 when not. The body never says why:
// the endpoint is public, and the reason goes to the log.
func (rd *readiness) handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if err := rd.result(r.Context()); err != nil {
		respondJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable"})
		return
	}
	respondJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}
