package server

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/reqctx"
)

// captureLogs routes the default logger into a buffer for one test.
func captureLogs(t *testing.T) func() []map[string]any {
	t.Helper()
	var buf bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return func() []map[string]any {
		var out []map[string]any
		for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
			if line == "" {
				continue
			}
			var rec map[string]any
			require.NoError(t, json.Unmarshal([]byte(line), &rec), line)
			out = append(out, rec)
		}
		return out
	}
}

// loggedRouter wires only the two middlewares under test around a few routes.
func loggedRouter() http.Handler {
	r := chi.NewRouter()
	r.Use(RequestIDMiddleware)
	r.Use(LoggerMiddleware)
	r.Get("/things/{id}", func(w http.ResponseWriter, req *http.Request) {
		time.Sleep(5 * time.Millisecond)
		w.WriteHeader(http.StatusNotFound)
	})
	r.Get("/invites/{token}", func(w http.ResponseWriter, req *http.Request) { w.WriteHeader(http.StatusOK) })
	r.Get("/boom", func(w http.ResponseWriter, req *http.Request) { w.WriteHeader(http.StatusInternalServerError) })
	r.Get("/api/v1/health", func(w http.ResponseWriter, req *http.Request) { w.WriteHeader(http.StatusOK) })
	r.Get("/api/v1/ready", func(w http.ResponseWriter, req *http.Request) { w.WriteHeader(http.StatusOK) })
	r.Get("/whoami", func(w http.ResponseWriter, req *http.Request) {
		_, _ = w.Write([]byte(reqctx.ID(req.Context())))
	})
	return r
}

func serve(h http.Handler, method, path string, header map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	for k, v := range header {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func requestRecords(all []map[string]any) []map[string]any {
	var out []map[string]any
	for _, rec := range all {
		if rec["msg"] == "request" {
			out = append(out, rec)
		}
	}
	return out
}

func TestRequestLog_OneLineAfterTheResponseWithStatusAndDuration(t *testing.T) {
	logs := captureLogs(t)

	w := serve(loggedRouter(), http.MethodGet, "/things/42?token=hunter2", nil)

	recs := requestRecords(logs())
	require.Len(t, recs, 1, "one line per request, written when it finishes")
	rec := recs[0]
	assert.Equal(t, "GET", rec["method"])
	assert.Equal(t, "/things/{id}", rec["route"])
	assert.EqualValues(t, 404, rec["status"])
	assert.GreaterOrEqual(t, rec["duration_ms"], float64(5))
	assert.Equal(t, w.Header().Get("X-Request-Id"), rec["request_id"], "the header and the log line carry the same id")
	assert.NotContains(t, rec, "query", "a query string can hold a token")
}

func TestRequestLog_LogsTheRoutePatternSoTokensStayOutOfTheLog(t *testing.T) {
	logs := captureLogs(t)

	serve(loggedRouter(), http.MethodGet, "/invites/SECRET-INVITE-TOKEN-123", nil)

	recs := requestRecords(logs())
	require.Len(t, recs, 1)
	assert.Equal(t, "/invites/{token}", recs[0]["route"])
	raw, err := json.Marshal(recs)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "SECRET-INVITE-TOKEN-123")
}

func TestRequestLog_UnmatchedPathsAreNotEchoed(t *testing.T) {
	logs := captureLogs(t)

	serve(loggedRouter(), http.MethodGet, "/wp-admin/%0d%0aFAKE-LINE", nil)

	recs := requestRecords(logs())
	require.Len(t, recs, 1)
	assert.Equal(t, "(unmatched)", recs[0]["route"])
	assert.EqualValues(t, 404, recs[0]["status"])
}

func TestRequestLog_ServerErrorsLogAtErrorLevelAndOthersAtInfo(t *testing.T) {
	logs := captureLogs(t)
	h := loggedRouter()

	serve(h, http.MethodGet, "/boom", nil)
	serve(h, http.MethodGet, "/things/1", nil)
	serve(h, http.MethodGet, "/invites/x", nil)

	recs := requestRecords(logs())
	require.Len(t, recs, 3)
	assert.Equal(t, "ERROR", recs[0]["level"])
	assert.Equal(t, "INFO", recs[1]["level"], "a 404 is the client's mistake, not an error of ours")
	assert.Equal(t, "INFO", recs[2]["level"])
}

func TestRequestLog_ProbesLogAtDebugSoTheyDoNotDrownTheLog(t *testing.T) {
	logs := captureLogs(t)
	h := loggedRouter()

	serve(h, http.MethodGet, "/api/v1/health", nil)
	serve(h, http.MethodGet, "/api/v1/ready", nil)

	recs := requestRecords(logs())
	require.Len(t, recs, 2)
	for _, rec := range recs {
		assert.Equal(t, "DEBUG", rec["level"])
	}
}

func TestRequestID_AcceptsAShortPlainIDFromTheCaller(t *testing.T) {
	w := serve(loggedRouter(), http.MethodGet, "/whoami", map[string]string{"X-Request-Id": "trace-abc_123.4"})

	assert.Equal(t, "trace-abc_123.4", w.Header().Get("X-Request-Id"))
	assert.Equal(t, "trace-abc_123.4", w.Body.String(), "handlers and audit see the same id through the context")
}

func TestRequestID_ReplacesAnIDThatCouldForgeALogLine(t *testing.T) {
	for name, bad := range map[string]string{
		"too long":    strings.Repeat("a", 65),
		"spaces":      "two words",
		"quotes":      `a"b`,
		"json":        `{"level":"ERROR"}`,
		"non-ascii":   "café",
		"empty":       "",
		"just a dash": "-" + strings.Repeat("-", 70),
	} {
		t.Run(name, func(t *testing.T) {
			w := serve(loggedRouter(), http.MethodGet, "/whoami", map[string]string{"X-Request-Id": bad})
			got := w.Header().Get("X-Request-Id")
			assert.Regexp(t, regexp.MustCompile(`^[0-9a-f]{32}$`), got, "a fresh random id replaces it")
			assert.NotEqual(t, bad, got)
		})
	}
}

func TestRequestID_EachRequestGetsItsOwn(t *testing.T) {
	h := loggedRouter()
	a := serve(h, http.MethodGet, "/whoami", nil).Header().Get("X-Request-Id")
	b := serve(h, http.MethodGet, "/whoami", nil).Header().Get("X-Request-Id")
	assert.NotEqual(t, a, b)
	assert.Len(t, a, 32)
}

func TestRequestID_TheContextAlsoCarriesTheStartTime(t *testing.T) {
	var start time.Time
	h := RequestIDMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start = reqctx.Start(r.Context())
	}))
	before := time.Now()
	serve(h, http.MethodGet, "/", nil)
	assert.False(t, start.Before(before))
	assert.False(t, start.After(time.Now()))
}
