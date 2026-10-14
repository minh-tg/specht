package audit

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/reqctx"
)

func auditEntry(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	var entry map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &entry), buf.String())
	return entry
}

// An audit line must be joinable to the access log line of the same request,
// and its duration must measure the request, not the instant it was written.
func TestHTTPCarriesTheRequestIDAndTheRealDuration(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(slog.New(slog.NewJSONHandler(&buf, nil)))
	req := httptest.NewRequest("POST", "/", nil)
	req = req.WithContext(reqctx.With(req.Context(), "rid-123", time.Now().Add(-250*time.Millisecond)))

	logger.HTTP(req, EventLogin, OutcomeSuccess, "", "", nil)

	entry := auditEntry(t, &buf)
	assert.Equal(t, "rid-123", entry["request_id"])
	assert.GreaterOrEqual(t, entry["duration_ms"], float64(250))
}

func TestHTTPOutsideARequestContextStillLogs(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(slog.New(slog.NewJSONHandler(&buf, nil)))

	logger.HTTP(httptest.NewRequest("POST", "/", nil), EventLogin, OutcomeFailure, "", "", nil)

	entry := auditEntry(t, &buf)
	assert.Equal(t, "", entry["request_id"])
	assert.GreaterOrEqual(t, entry["duration_ms"], float64(0))
}
