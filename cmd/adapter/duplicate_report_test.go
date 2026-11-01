package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/client"
)

// duplicateServer answers every upload with 409 duplicate_report, as the server
// does when it already holds the same report, and serves the stored verdict
// from the gate and PR check routes. It counts the uploads.
type duplicateServer struct {
	*httptest.Server
	uploads int
	// previewQuery holds the last PR check query string.
	previewQuery string
}

func newDuplicateServer(t *testing.T, gate *client.GateStatus, preview *client.PRCheckPreview) *duplicateServer {
	t.Helper()
	d := &duplicateServer{}
	d.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/reports":
			d.uploads++
			w.WriteHeader(http.StatusConflict)
			writeTestJSONResponse(t, w, map[string]any{
				"error": map[string]string{"code": "duplicate_report", "message": "report already exists for this project and data"},
			})
		case "/api/v1/projects/my-app/gate":
			if gate == nil {
				http.Error(w, `{"error":{"code":"internal","message":"boom"}}`, http.StatusInternalServerError)
				return
			}
			writeTestJSONResponse(t, w, gate)
		case "/api/v1/projects/my-app/pr-check":
			d.previewQuery = r.URL.RawQuery
			if preview == nil {
				http.Error(w, `{"error":{"code":"no_report_for_commit","message":"none"}}`, http.StatusNotFound)
				return
			}
			writeTestJSONResponse(t, w, preview)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(d.Close)
	return d
}

func runDuplicate(t *testing.T, d *duplicateServer, args ...string) (code int, stderr string) {
	t.Helper()
	slept := stubRetrySleep(t)
	clearCIEnvironment(t)
	t.Setenv("API_KEY", "test-key")
	t.Setenv("API_URL", d.URL)
	var out, errOut bytes.Buffer
	base := []string{"-project=my-app", "-tool=trivy"}
	code = run(append(base, args...), strings.NewReader(`{"Results":[]}`), &out, &errOut, d.Client())
	assert.Equal(t, 1, d.uploads, "a 409 duplicate is not retried")
	assert.Empty(t, *slept)
	return code, errOut.String()
}

func TestRun_DuplicateReportExitsAsTheStoredProjectVerdict(t *testing.T) {
	t.Run("passing", func(t *testing.T) {
		d := newDuplicateServer(t, &client.GateStatus{}, nil)
		code, stderr := runDuplicate(t, d)
		require.Equal(t, 0, code, stderr)
		assert.Contains(t, stderr, "already uploaded")
		assert.Contains(t, stderr, "gate PASSED")
	})
	t.Run("breached", func(t *testing.T) {
		d := newDuplicateServer(t, &client.GateStatus{ThresholdBreached: true, BlockingCount: 2}, nil)
		code, stderr := runDuplicate(t, d)
		require.Equal(t, 1, code, stderr)
		assert.Contains(t, stderr, "already uploaded")
		assert.Contains(t, stderr, "gate FAILED: 2 blocking finding(s)")
	})
	t.Run("gate unreadable", func(t *testing.T) {
		d := newDuplicateServer(t, nil, nil)
		code, stderr := runDuplicate(t, d)
		require.Equal(t, 2, code, stderr)
		assert.Contains(t, stderr, "gate check failed")
	})
}

func TestRun_DuplicateReportExitsAsTheStoredChangeVerdict(t *testing.T) {
	args := []string{"-introduced-only", "-commit=abcdef1"}
	t.Run("passing", func(t *testing.T) {
		d := newDuplicateServer(t, nil, &client.PRCheckPreview{Conclusion: "success"})
		code, stderr := runDuplicate(t, d, args...)
		require.Equal(t, 0, code, stderr)
		assert.Contains(t, stderr, "already uploaded")
		assert.Contains(t, stderr, "SPECHT SECURITY GATE: PASSED")
		assert.Contains(t, d.previewQuery, "commit=abcdef1")
		assert.NotContains(t, d.previewQuery, "report_id")
	})
	t.Run("breached", func(t *testing.T) {
		d := newDuplicateServer(t, nil, &client.PRCheckPreview{
			Conclusion:    "failure",
			SummaryCounts: map[string]int{"high": 2},
			Annotations: []client.PRCheckAnnotation{
				{File: "go.mod", StartLine: 3, Level: "error", Title: "libfoo 1.0"},
			},
		})
		code, stderr := runDuplicate(t, d, args...)
		require.Equal(t, 1, code, stderr)
		assert.Contains(t, stderr, "SPECHT SECURITY GATE: FAILED")
		assert.Contains(t, stderr, "libfoo 1.0")
	})
	t.Run("breached without mappable annotations counts the findings", func(t *testing.T) {
		d := newDuplicateServer(t, nil, &client.PRCheckPreview{Conclusion: "failure", SummaryCounts: map[string]int{"high": 2, "low": 1}})
		code, stderr := runDuplicate(t, d, args...)
		require.Equal(t, 1, code, stderr)
		assert.Contains(t, stderr, "NEW BLOCKING FINDINGS INTRODUCED IN THIS CHANGE: 3")
	})
	t.Run("verdict unreadable fails closed", func(t *testing.T) {
		d := newDuplicateServer(t, nil, nil)
		code, stderr := runDuplicate(t, d, args...)
		require.Equal(t, 2, code, stderr)
		assert.Contains(t, stderr, "stored verdict could not be read")
	})
	t.Run("no commit means no verdict to read", func(t *testing.T) {
		d := newDuplicateServer(t, nil, &client.PRCheckPreview{Conclusion: "success"})
		code, stderr := runDuplicate(t, d, "-introduced-only")
		require.Equal(t, 2, code, stderr)
		assert.Contains(t, stderr, "duplicate report")
	})
}
