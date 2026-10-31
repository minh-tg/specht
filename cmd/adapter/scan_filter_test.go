package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/client"
)

// runForScanFilter runs the adapter against a fake server and returns the
// ingest request body it sent, decoded loosely so an omitted scan_filter is
// told apart from an empty one.
func runForScanFilter(t *testing.T, args ...string) map[string]any {
	t.Helper()
	t.Setenv("API_KEY", "test-key")
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/reports":
			assert.NoError(t, json.NewDecoder(r.Body).Decode(&body))
			writeTestJSONResponse(t, w, client.IngestResponse{ReportID: "rep-1"})
		case "/api/v1/projects/my-app/gate":
			writeTestJSONResponse(t, w, client.GateStatus{})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	t.Setenv("API_URL", srv.URL)

	var stdout, stderr bytes.Buffer
	base := []string{"-file=../../internal/parser/trivy/testdata/alpine-scan.json", "-project=my-app"}
	code := run(append(base, args...), bytes.NewReader(nil), &stdout, &stderr, srv.Client())
	require.Equal(t, 0, code, stderr.String())
	return body
}

func TestRun_ScanFilterFlagsReachTheRequest(t *testing.T) {
	clearCIEnvironment(t)
	body := runForScanFilter(t, "-tool=grype", "-scan-severities=high, CRITICAL", "-fixable-only")
	assert.Equal(t, map[string]any{
		"severities":   []any{"high", "CRITICAL"},
		"fixable_only": true,
	}, body["scan_filter"])
}

func TestRun_ScanFilterAbsentWhenNothingIsDeclared(t *testing.T) {
	clearCIEnvironment(t)
	body := runForScanFilter(t, "-tool=trivy")
	assert.NotContains(t, body, "scan_filter")
}

func TestRun_TrivyEnvironmentDeclaresTheFilter(t *testing.T) {
	clearCIEnvironment(t)
	t.Setenv("TRIVY_SEVERITY", "HIGH,CRITICAL")
	t.Setenv("TRIVY_IGNORE_UNFIXED", "true")
	body := runForScanFilter(t, "-tool=trivy")
	assert.Equal(t, map[string]any{
		"severities":   []any{"HIGH", "CRITICAL"},
		"fixable_only": true,
	}, body["scan_filter"])
}

func TestRun_FlagsWinOverTheTrivyEnvironment(t *testing.T) {
	clearCIEnvironment(t)
	t.Setenv("TRIVY_SEVERITY", "LOW")
	t.Setenv("TRIVY_IGNORE_UNFIXED", "true")
	body := runForScanFilter(t, "-tool=trivy", "-scan-severities=critical", "-fixable-only=false")
	assert.Equal(t, map[string]any{"severities": []any{"critical"}}, body["scan_filter"])
}

func TestRun_TrivyEnvironmentIsIgnoredForOtherScanners(t *testing.T) {
	clearCIEnvironment(t)
	t.Setenv("TRIVY_SEVERITY", "HIGH")
	t.Setenv("TRIVY_IGNORE_UNFIXED", "true")
	body := runForScanFilter(t, "-tool=grype")
	assert.NotContains(t, body, "scan_filter")
}

func TestApplyScanFilter_TrivyEnvironmentEdgeCases(t *testing.T) {
	for name, tc := range map[string]struct {
		severity, unfixed string
		want              *client.ScanFilter
	}{
		"blank severity entries":    {" , ", "", nil},
		"unfixed false":             {"", "false", nil},
		"unfixed not a boolean":     {"", "yes please", nil},
		"unfixed 1":                 {"", "1", &client.ScanFilter{FixableOnly: true}},
		"severity with spaces":      {"HIGH, CRITICAL,", "", &client.ScanFilter{Severities: []string{"HIGH", "CRITICAL"}}},
		"both set":                  {"MEDIUM", "TRUE", &client.ScanFilter{Severities: []string{"MEDIUM"}, FixableOnly: true}},
		"neither set":               {"", "", nil},
		"severity only blank entry": {",", "", nil},
	} {
		t.Run(name, func(t *testing.T) {
			clearCIEnvironment(t)
			t.Setenv("TRIVY_SEVERITY", tc.severity)
			t.Setenv("TRIVY_IGNORE_UNFIXED", tc.unfixed)
			payload := client.IngestPayload{Scanner: "Trivy"}
			applyScanFilter(&payload, &adapterFlags{})
			assert.Equal(t, tc.want, payload.ScanFilter)
		})
	}
}

func TestParseFlags_FixableOnlyRejectsNonBoolean(t *testing.T) {
	clearCIEnvironment(t)
	var stderr bytes.Buffer
	assert.Nil(t, parseFlags([]string{"-fixable-only=maybe"}, &stderr, false))
}
