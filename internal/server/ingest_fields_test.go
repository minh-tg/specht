package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/usecase"
)

func TestIngestRequest_InvalidFieldNamesTheFirstBadField(t *testing.T) {
	ok := ingestRequest{Project: "p", Scanner: "trivy", Branch: "feature/x", CommitSha: "9fceb02d0ae598e95dc970b74767f19372d61af8", Environment: "production"}
	tests := []struct {
		name  string
		edit  func(r *ingestRequest)
		field string
	}{
		{"clean request", func(*ingestRequest) {}, ""},
		{"commit_sha at the cap", func(r *ingestRequest) { r.CommitSha = strings.Repeat("a", 64) }, ""},
		{"commit_sha over the cap", func(r *ingestRequest) { r.CommitSha = strings.Repeat("a", 65) }, "commit_sha"},
		{"commit_sha with a space", func(r *ingestRequest) { r.CommitSha = "abc def" }, "commit_sha"},
		{"commit_sha with markdown", func(r *ingestRequest) { r.CommitSha = "[x](http://e)" }, "commit_sha"},
		{"commit_sha with punctuation git allows", func(r *ingestRequest) { r.CommitSha = "v1.2.3_rc-1" }, ""},
		{"branch at the cap", func(r *ingestRequest) { r.Branch = strings.Repeat("b", 255) }, ""},
		{"branch over the cap", func(r *ingestRequest) { r.Branch = strings.Repeat("b", 256) }, "branch"},
		{"branch with a newline", func(r *ingestRequest) { r.Branch = "main\nevil" }, "branch"},
		{"branch with an escape", func(r *ingestRequest) { r.Branch = "main\x1b[31m" }, "branch"},
		{"branch with a DEL", func(r *ingestRequest) { r.Branch = "main\x7f" }, "branch"},
		{"multibyte branch counts bytes", func(r *ingestRequest) { r.Branch = strings.Repeat("é", 128) }, "branch"},
		{"environment over the cap", func(r *ingestRequest) { r.Environment = strings.Repeat("e", 65) }, "environment"},
		{"environment with a tab", func(r *ingestRequest) { r.Environment = "pro\td" }, "environment"},
		{"base_revision over the cap", func(r *ingestRequest) { r.BaseRevision = strings.Repeat("r", 256) }, "base_revision"},
		{"owner over the cap", func(r *ingestRequest) { r.Owner = strings.Repeat("o", 256) }, "owner"},
		{"digest over the cap", func(r *ingestRequest) { r.Digest = strings.Repeat("d", 256) }, "digest"},
		{"artifact_name over the cap", func(r *ingestRequest) { r.ArtifactName = strings.Repeat("n", 256) }, "artifact_name"},
		{"artifact_version over the cap", func(r *ingestRequest) { r.ArtifactVersion = strings.Repeat("v", 256) }, "artifact_version"},
		{"artifact_type over the cap", func(r *ingestRequest) { r.ArtifactType = strings.Repeat("t", 256) }, "artifact_type"},
		{"changed_files at the cap", func(r *ingestRequest) { r.ChangedFiles = make([]string, 5000) }, ""},
		{"changed_files over the cap", func(r *ingestRequest) { r.ChangedFiles = make([]string, 5001) }, "changed_files"},
		{"changed_files entry at the cap", func(r *ingestRequest) { r.ChangedFiles = []string{strings.Repeat("f", 1024)} }, ""},
		{"changed_files entry over the cap", func(r *ingestRequest) { r.ChangedFiles = []string{"a.go", strings.Repeat("f", 1025)} }, "changed_files"},
		{"changed_files entry with a newline", func(r *ingestRequest) { r.ChangedFiles = []string{"a.go\nb.go"} }, "changed_files"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := ok
			tc.edit(&r)
			field, problem := r.invalidField()
			assert.Equal(t, tc.field, field)
			assert.Equal(t, tc.field == "", problem == "", "a problem is reported exactly when a field is named")
		})
	}
}

func TestIngestRequest_InvalidFieldKeepsTheNULMessage(t *testing.T) {
	field, problem := ingestRequest{Project: "p", Scanner: "s", Environment: "a\x00b"}.invalidField()
	assert.Equal(t, "environment", field)
	assert.Equal(t, "must not contain a NUL character", problem)
}

// A bad metadata field is refused by name before the use case runs, so no
// environment, target or artifact row can be created for it.
func TestIngestReport_RefusesBadMetadataByName(t *testing.T) {
	for field, value := range map[string]string{
		"commit_sha":    strings.Repeat("a", 1<<20),
		"branch":        "main\r\nInjected: header",
		"environment":   strings.Repeat("e", 65),
		"artifact_name": strings.Repeat("n", 256),
		"owner":         "own\x1ber",
	} {
		t.Run(field, func(t *testing.T) {
			called := false
			mock := &mockUsecases{
				ingestReportFn: func(context.Context, usecase.IngestReportInput) (*usecase.IngestReportOutput, error) {
					called = true
					return &usecase.IngestReportOutput{ReportID: "rep-1"}, nil
				},
			}
			// The project comes first: a body that buries it behind a megabyte of
			// metadata is refused before its fields are read.
			val, err := json.Marshal(value)
			require.NoError(t, err)
			raw := fmt.Sprintf(`{"project":"my-app","scanner":"trivy","raw_data":{"a":1},%q:%s}`, field, val)
			req := httptest.NewRequest("POST", "/api/v1/reports", strings.NewReader(raw))
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
