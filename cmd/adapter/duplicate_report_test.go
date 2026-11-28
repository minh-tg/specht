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
	// introduced answers the introduced-only gate; nil answers 404.
	introduced *client.GateStatus
	// introducedQuery holds the last introduced-only gate query string.
	introducedQuery string
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
			if r.URL.Query().Get("introduced_only") != "" {
				d.introducedQuery = r.URL.RawQuery
				if d.introduced == nil {
					http.Error(w, `{"error":{"code":"no_report_for_commit","message":"none"}}`, http.StatusNotFound)
					return
				}
				writeTestJSONResponse(t, w, d.introduced)
				return
			}
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
	t.Run("report only says the gate would fail", func(t *testing.T) {
		d := newDuplicateServer(t, nil, &client.PRCheckPreview{Conclusion: "neutral", SummaryCounts: map[string]int{"high": 2}})
		code, stderr := runDuplicate(t, d, args...)
		require.Equal(t, 0, code, stderr)
		assert.Contains(t, stderr, "SPECHT SECURITY GATE: WOULD FAIL")
		assert.Contains(t, stderr, "2 finding(s) this change introduced would block it.")
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

// TestRun_DuplicateReportKeepsTheChangesOnlyVerdict pins a push build of a branch
// under changes_only that uploads the same report again. The first run failed on
// what its report introduced. The 409 names no report, so the rerun judges what
// the commit introduced and fails the same way.
func TestRun_DuplicateReportKeepsTheChangesOnlyVerdict(t *testing.T) {
	const commit = "0123456789abcdef0123456789abcdef01234567"
	changesOnly := &client.PolicyEffective{GateMode: "changes_only"}
	debt := &client.GateStatus{ThresholdBreached: true, ReportOnly: true, BlockingCount: 3, Policy: changesOnly}
	t.Run("a branch that introduced a blocker fails again", func(t *testing.T) {
		d := newDuplicateServer(t, debt, nil)
		d.introduced = &client.GateStatus{ThresholdBreached: true, BlockingCount: 1, Policy: changesOnly}
		code, stderr := runDuplicate(t, d, "-introduced-only=false", "-branch=feat/x", "-base-ref=main", "-commit="+commit)
		require.Equal(t, 1, code, stderr)
		assert.Contains(t, stderr, "gate FAILED: 1 blocking finding(s) from trivy")
		assert.Contains(t, d.introducedQuery, "commit="+commit)
		assert.NotContains(t, d.introducedQuery, "report_id")
	})
	t.Run("a branch that only carries debt still passes", func(t *testing.T) {
		d := newDuplicateServer(t, debt, nil)
		d.introduced = &client.GateStatus{Policy: changesOnly}
		code, stderr := runDuplicate(t, d, "-introduced-only=false", "-branch=feat/x", "-base-ref=main", "-commit="+commit)
		require.Equal(t, 0, code, stderr)
		assert.Contains(t, stderr, "gate WOULD FAIL: 3 blocking finding(s)")
	})
	t.Run("a scan of the trunk is not a change", func(t *testing.T) {
		d := newDuplicateServer(t, debt, nil)
		d.introduced = &client.GateStatus{ThresholdBreached: true, BlockingCount: 3, Policy: changesOnly}
		code, stderr := runDuplicate(t, d, "-branch=main", "-commit="+commit)
		require.Equal(t, 0, code, stderr)
		assert.Contains(t, stderr, "gate WOULD FAIL: 3 blocking finding(s)")
		assert.Empty(t, d.introducedQuery, "the trunk's first scan introduces its whole backlog, which only reports")
	})
	t.Run("the stored report gone fails closed", func(t *testing.T) {
		d := newDuplicateServer(t, debt, nil)
		code, stderr := runDuplicate(t, d, "-introduced-only=false", "-branch=feat/x", "-base-ref=main", "-commit="+commit)
		require.Equal(t, 2, code, stderr)
		assert.Contains(t, stderr, "gate check failed")
	})
}
