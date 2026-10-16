package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/usecase"
)

// A NUL in one of the request's text fields is refused by name before the use
// case runs: PostgreSQL would refuse it and the caller would only see a generic
// ingest_failed.
func TestIngestReport_RefusesANULInARequestField(t *testing.T) {
	fields := []string{
		"project", "scanner", "scanner_version", "parser_version", "branch", "commit_sha", "base_revision",
		"scan_mode", "gate_severity", "gate_status", "environment", "owner", "digest",
		"artifact_name", "artifact_version", "artifact_type",
	}
	for _, field := range append(fields, "changed_files") {
		t.Run(field, func(t *testing.T) {
			called := false
			mock := &mockUsecases{
				ingestReportFn: func(context.Context, usecase.IngestReportInput) (*usecase.IngestReportOutput, error) {
					called = true
					return &usecase.IngestReportOutput{ReportID: "rep-1"}, nil
				},
			}
			body := map[string]any{"project": "my-app", "scanner": "trivy", "raw_data": json.RawMessage(`{"a":1}`)}
			if field == "changed_files" {
				body[field] = []string{"ok.go", "bad\x00.go"}
			} else {
				body[field] = "a\x00b"
			}
			raw, err := json.Marshal(body)
			require.NoError(t, err)
			req := httptest.NewRequest("POST", "/api/v1/reports", strings.NewReader(string(raw)))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+testToken(t))
			w := httptest.NewRecorder()

			NewRouter(RouterConfig{Usecases: mock, JWTAuth: testJWTAuth}).ServeHTTP(w, req)

			requireAPIError(t, w, http.StatusBadRequest, "invalid_field")
			assert.Contains(t, w.Body.String(), field)
			assert.False(t, called, "the use case must not see the request")
		})
	}
}

func TestIngestRequest_FieldWithNULIsEmptyForACleanRequest(t *testing.T) {
	assert.Empty(t, ingestRequest{Project: "p", Scanner: "s", Branch: "main", ChangedFiles: []string{"a.go"}}.fieldWithNUL())
}
