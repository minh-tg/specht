package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/domain"
	"github.com/minh-tg/specht/internal/usecase"
)

func postScanFilterIngest(t *testing.T, mock *mockUsecases, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", "/api/v1/reports", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+testToken(t))
	w := httptest.NewRecorder()
	NewRouter(RouterConfig{Usecases: mock, JWTAuth: testJWTAuth}).ServeHTTP(w, req)
	return w
}

func TestIngestReport_RefusesAnUnknownScanFilterSeverity(t *testing.T) {
	for name, filter := range map[string]string{
		"unknown name":   `{"severities":["high","severe"]}`,
		"wrong type":     `{"severities":["negligible"]}`,
		"blank":          `{"severities":[""]}`,
		"too many":       `{"severities":["a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q"]}`,
		"long entry":     `{"severities":["` + strings.Repeat("h", 33) + `"]}`,
		"control escape": `{"severities":["hi\u001bgh"]}`,
	} {
		t.Run(name, func(t *testing.T) {
			called := false
			mock := &mockUsecases{
				ingestReportFn: func(context.Context, usecase.IngestReportInput) (*usecase.IngestReportOutput, error) {
					called = true
					return &usecase.IngestReportOutput{ReportID: "rep-1"}, nil
				},
			}
			w := postScanFilterIngest(t, mock, `{"project":"my-app","scanner":"trivy","raw_data":{"a":1},"scan_filter":`+filter+`}`)

			requireAPIError(t, w, http.StatusBadRequest, "invalid_field")
			assert.Contains(t, w.Body.String(), "scan_filter.severities")
			assert.False(t, called, "the use case must not see the request")
		})
	}
}

func TestIngestReport_PassesTheNormalizedScanFilter(t *testing.T) {
	var got usecase.IngestReportInput
	mock := &mockUsecases{
		ingestReportFn: func(_ context.Context, in usecase.IngestReportInput) (*usecase.IngestReportOutput, error) {
			got = in
			return &usecase.IngestReportOutput{ReportID: "rep-1", ScanMode: "full"}, nil
		},
	}
	w := postScanFilterIngest(t, mock, `{"project":"my-app","scanner":"trivy","raw_data":{"a":1},"scan_filter":{"severities":["CRITICAL","High","high"],"fixable_only":true}}`)

	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	assert.Equal(t, domain.ScanFilter{Severities: []string{"high", "critical"}, FixableOnly: true}, got.ScanFilter)
}

func TestIngestReport_NoScanFilterMeansNoFilter(t *testing.T) {
	for name, body := range map[string]string{
		"absent": `{"project":"my-app","scanner":"trivy","raw_data":{"a":1}}`,
		"empty":  `{"project":"my-app","scanner":"trivy","raw_data":{"a":1},"scan_filter":{"severities":[]}}`,
		"null":   `{"project":"my-app","scanner":"trivy","raw_data":{"a":1},"scan_filter":null}`,
	} {
		t.Run(name, func(t *testing.T) {
			var got usecase.IngestReportInput
			mock := &mockUsecases{
				ingestReportFn: func(_ context.Context, in usecase.IngestReportInput) (*usecase.IngestReportOutput, error) {
					got = in
					return &usecase.IngestReportOutput{ReportID: "rep-1", ScanMode: "full"}, nil
				},
			}
			w := postScanFilterIngest(t, mock, body)

			require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
			assert.True(t, got.ScanFilter.IsZero())
		})
	}
}
