package server

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/usecase"
)

func TestIngestReport_PassesWhereTheReportCameFrom(t *testing.T) {
	var got usecase.IngestReportInput
	mock := &mockUsecases{
		ingestReportFn: func(_ context.Context, in usecase.IngestReportInput) (*usecase.IngestReportOutput, error) {
			got = in
			return &usecase.IngestReportOutput{ReportID: "rep-1", ScanMode: "full"}, nil
		},
	}
	w := postScanFilterIngest(t, mock, `{"project":"my-app","scanner":"trivy","raw_data":{"a":1},`+
		`"repository_url":"https://github.com/acme/shop","pull_request_number":123,`+
		`"pull_request_title":"Bump lodash","ci_run_url":"https://github.com/acme/shop/actions/runs/42"}`)

	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	assert.Equal(t, "https://github.com/acme/shop", got.RepositoryURL)
	assert.Equal(t, int32(123), got.PullRequestNumber)
	assert.Equal(t, "Bump lodash", got.PullRequestTitle)
	assert.Equal(t, "https://github.com/acme/shop/actions/runs/42", got.CIRunURL)
}

// A link the UI would render must be refused before the use case runs.
func TestIngestReport_RefusesALinkThatIsNotHTTP(t *testing.T) {
	for field, body := range map[string]string{
		"repository_url":      `"repository_url":"javascript:alert(1)"`,
		"ci_run_url":          `"ci_run_url":"https://user:pass@ci.example.com/run/1"`,
		"pull_request_number": `"pull_request_number":-4`,
	} {
		t.Run(field, func(t *testing.T) {
			called := false
			mock := &mockUsecases{
				ingestReportFn: func(context.Context, usecase.IngestReportInput) (*usecase.IngestReportOutput, error) {
					called = true
					return &usecase.IngestReportOutput{ReportID: "rep-1"}, nil
				},
			}
			w := postScanFilterIngest(t, mock, `{"project":"my-app","scanner":"trivy","raw_data":{"a":1},`+body+`}`)

			requireAPIError(t, w, http.StatusBadRequest, "invalid_field")
			assert.Contains(t, w.Body.String(), field)
			assert.False(t, called, "the use case must not see the request")
		})
	}
}
