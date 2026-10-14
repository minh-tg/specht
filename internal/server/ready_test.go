package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func getReady(t *testing.T, cfg RouterConfig) *httptest.ResponseRecorder {
	t.Helper()
	if cfg.Usecases == nil {
		cfg.Usecases = &mockUsecases{}
	}
	cfg.JWTAuth = testJWTAuth
	req := httptest.NewRequest(http.MethodGet, "/api/v1/ready", nil)
	w := httptest.NewRecorder()
	NewRouter(cfg).ServeHTTP(w, req)
	return w
}

func readyStatus(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var body map[string]string
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	return body["status"]
}

func TestReady_AnsweredWithoutASessionAndWithoutACheckConfigured(t *testing.T) {
	w := getReady(t, RouterConfig{})

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "ready", readyStatus(t, w))
}

func TestReady_ReadyWhenTheCheckPasses(t *testing.T) {
	w := getReady(t, RouterConfig{Ready: func(ctx context.Context) error { return nil }})

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "ready", readyStatus(t, w))
}

func TestReady_UnavailableWhenTheCheckFailsAndNeverLeaksWhy(t *testing.T) {
	w := getReady(t, RouterConfig{Ready: func(ctx context.Context) error {
		return errors.New("dial tcp 10.0.0.5:5432: connection refused")
	}})

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Equal(t, "unavailable", readyStatus(t, w))
	assert.NotContains(t, w.Body.String(), "10.0.0.5", "an unauthenticated caller learns nothing about the network")
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"), "a probe answer is never cached by a proxy")
}

func TestReady_TheCheckGetsADeadline(t *testing.T) {
	var hadDeadline bool
	rd := newReadiness(func(ctx context.Context) error {
		_, hadDeadline = ctx.Deadline()
		return nil
	})

	rd.handler(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))

	assert.True(t, hadDeadline, "a database that hangs must not hang the probe")
}

func TestReady_ASlowCheckIsUnavailable(t *testing.T) {
	rd := newReadiness(func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	})
	rd.timeout = 20 * time.Millisecond
	w := httptest.NewRecorder()

	rd.handler(w, httptest.NewRequest(http.MethodGet, "/", nil))

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestReady_RepeatedProbesShareOneDatabaseCheck(t *testing.T) {
	var calls atomic.Int32
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	rd := newReadiness(func(ctx context.Context) error {
		calls.Add(1)
		return nil
	})
	rd.now = func() time.Time { return now }

	for range 50 {
		rd.handler(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	}
	assert.Equal(t, int32(1), calls.Load(), "an unauthenticated caller cannot turn the probe into database load")

	now = now.Add(readyCacheTTL + time.Millisecond)
	rd.handler(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	assert.Equal(t, int32(2), calls.Load(), "the answer is fresh again after the window")
}

func TestReady_AFailureIsCachedToo(t *testing.T) {
	var calls atomic.Int32
	rd := newReadiness(func(ctx context.Context) error {
		calls.Add(1)
		return errors.New("down")
	})

	for range 10 {
		w := httptest.NewRecorder()
		rd.handler(w, httptest.NewRequest(http.MethodGet, "/", nil))
		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	}
	assert.Equal(t, int32(1), calls.Load())
}

func TestReady_RecoversWhenTheDatabaseReturns(t *testing.T) {
	healthy := false
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	rd := newReadiness(func(ctx context.Context) error {
		if healthy {
			return nil
		}
		return errors.New("down")
	})
	rd.now = func() time.Time { return now }

	w := httptest.NewRecorder()
	rd.handler(w, httptest.NewRequest(http.MethodGet, "/", nil))
	require.Equal(t, http.StatusServiceUnavailable, w.Code)

	healthy = true
	now = now.Add(2 * readyCacheTTL)
	w = httptest.NewRecorder()
	rd.handler(w, httptest.NewRequest(http.MethodGet, "/", nil))
	assert.Equal(t, http.StatusOK, w.Code)
}
