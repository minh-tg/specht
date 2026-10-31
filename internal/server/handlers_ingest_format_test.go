package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/scanner"
	"github.com/minh-tg/specht/internal/usecase"
)

func ingestWithError(t *testing.T, scannerName string, err error) (int, struct{ Code, Message string }) {
	t.Helper()
	mock := &mockUsecases{
		ingestReportFn: func(context.Context, usecase.IngestReportInput) (*usecase.IngestReportOutput, error) {
			return nil, err
		},
	}
	body := strings.NewReader(`{"project":"my-app","scanner":"` + scannerName + `","raw_data":{}}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/reports", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	testRouter(mock).ServeHTTP(w, req)

	var resp struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	return w.Code, struct{ Code, Message string }{resp.Error.Code, resp.Error.Message}
}

func TestIngestReport_NamesTheScannerTheFileLooksLike(t *testing.T) {
	err := fmt.Errorf("wrapped: %w", &scanner.UnrecognizedFormatError{Scanner: "trivy", LooksLike: []string{"grype"}})

	status, got := ingestWithError(t, "trivy", err)

	assert.Equal(t, http.StatusUnprocessableEntity, status)
	assert.Equal(t, "unrecognized_format", got.Code)
	assert.Equal(t, "The file is not trivy output. It looks like grype output; choose grype as the scanner.", got.Message)
}

func TestIngestReport_UnrecognizedWithNoSuggestion(t *testing.T) {
	status, got := ingestWithError(t, "trivy", &scanner.UnrecognizedFormatError{Scanner: "trivy"})

	assert.Equal(t, http.StatusUnprocessableEntity, status)
	assert.Equal(t, "unrecognized_format", got.Code)
	assert.Equal(t, "The file is not trivy output. Check that you chose the scanner that wrote it.", got.Message)
}

func TestIngestReport_MalformedReport(t *testing.T) {
	status, got := ingestWithError(t, "grype", fmt.Errorf("scanner grype: parse output: %w", scanner.Malformed("grype", errors.New("json: cannot unmarshal string into Go struct field grypeDoc.matches of type []grype.match"))))

	assert.Equal(t, http.StatusUnprocessableEntity, status)
	assert.Equal(t, "malformed_report", got.Code)
	assert.Equal(t, "The grype report could not be read. Check that the file is complete and came from a current version of the tool.", got.Message)
	assert.NotContains(t, got.Message, "Go struct", "parser internals stay out of the response")
}

func TestIngestReport_MalformedReportNamesTheSafeReason(t *testing.T) {
	err := fmt.Errorf("scanner sarif: parse output: %w", scanner.Malformed("sarif",
		scanner.Detail(`the file declares SARIF version "2.0.0"; this reader accepts 2.1.x`,
			errors.New("unsupported version"))))
	status, got := ingestWithError(t, "sarif", err)

	assert.Equal(t, http.StatusUnprocessableEntity, status)
	assert.Equal(t, "malformed_report", got.Code)
	assert.Equal(t, `The sarif report could not be read: the file declares SARIF version "2.0.0"; this reader accepts 2.1.x.`, got.Message)
}

func TestIngestReport_UnknownScanner(t *testing.T) {
	status, got := ingestWithError(t, "no-such-tool", fmt.Errorf("%w: %q", usecase.ErrUnknownScanner, "no-such-tool"))

	assert.Equal(t, http.StatusUnprocessableEntity, status)
	assert.Equal(t, "unknown_scanner", got.Code)
	assert.Contains(t, got.Message, "no-such-tool")
	assert.Contains(t, got.Message, "/api/v1/scanners")
}

func TestIngestReport_OtherFailuresStayGeneric(t *testing.T) {
	status, got := ingestWithError(t, "trivy", errors.New("pq: connection refused at 10.0.0.5"))

	assert.Equal(t, http.StatusUnprocessableEntity, status)
	assert.Equal(t, "ingest_failed", got.Code)
	assert.NotContains(t, got.Message, "10.0.0.5")
}

func TestIngestReport_TooManyFindingsNamesTheLimit(t *testing.T) {
	err := fmt.Errorf("scanner trivy: parse output: %w", scanner.TooManyFindings(100000))

	status, got := ingestWithError(t, "trivy", err)

	assert.Equal(t, http.StatusUnprocessableEntity, status)
	assert.Equal(t, "too_many_findings", got.Code)
	assert.Contains(t, got.Message, "100000", "the message names the limit")
	assert.Contains(t, got.Message, "Split", "and tells the user what to do")
	assert.Contains(t, got.Message, "findings", "the finding-count refusal still names findings")
	assert.NotContains(t, got.Message, "nests deeper", "and never claims a depth refusal")
}

func TestIngestReport_DenseRefusalSaysPackingNotFindings(t *testing.T) {
	// A real 1 MiB document of one-key objects, through the check the usecase runs.
	doc := `{"r":[` + strings.TrimSuffix(strings.Repeat(`{"a":0},`, (1<<20)/8), ",") + `]}`
	err := fmt.Errorf("scanner trivy: %w", scanner.CheckIngestDocument([]byte(doc), scanner.DefaultMaxFindings))

	status, got := ingestWithError(t, "trivy", err)

	assert.Equal(t, http.StatusUnprocessableEntity, status, "the status stays 422")
	assert.Equal(t, "too_many_findings", got.Code, "the code stays too_many_findings")
	assert.Contains(t, got.Message, "packs too many small JSON values")
	assert.NotContains(t, got.Message, "nests deeper")
	assert.NotContains(t, got.Message, "more than", "a dense refusal names no finding count")
}

func TestIngestReport_DepthRefusalSaysNestingNotFindings(t *testing.T) {
	// A real 65-level document, through the same CheckDocument the usecase runs.
	depth := scanner.MaxNestingDepth + 1
	doc := strings.Repeat(`{"k":`, depth) + "null" + strings.Repeat("}", depth)
	err := fmt.Errorf("scanner trivy: %w", scanner.CheckDocument([]byte(doc), scanner.DefaultMaxFindings))

	status, got := ingestWithError(t, "trivy", err)

	assert.Equal(t, http.StatusUnprocessableEntity, status, "the status stays 422")
	assert.Equal(t, "too_many_findings", got.Code, "the code stays too_many_findings")
	assert.Contains(t, got.Message, "nests deeper than 64 levels")
	assert.NotContains(t, got.Message, "findings", "a depth refusal must not talk about findings")
}
