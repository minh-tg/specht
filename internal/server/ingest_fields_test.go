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
		{"artifact_type from the vocabulary", func(r *ingestRequest) { r.ArtifactType = "container_image" }, ""},
		{"artifact_type with hyphens", func(r *ingestRequest) { r.ArtifactType = "container-image" }, ""},
		{"artifact_type outside the vocabulary", func(r *ingestRequest) { r.ArtifactType = "image" }, "artifact_type"},
		{"changed_files at the cap", func(r *ingestRequest) { r.ChangedFiles = make([]string, 5000) }, ""},
		{"changed_files over the cap", func(r *ingestRequest) { r.ChangedFiles = make([]string, 5001) }, "changed_files"},
		{"changed_files entry at the cap", func(r *ingestRequest) { r.ChangedFiles = []string{strings.Repeat("f", 1024)} }, ""},
		{"changed_files entry over the cap", func(r *ingestRequest) { r.ChangedFiles = []string{"a.go", strings.Repeat("f", 1025)} }, "changed_files"},
		{"changed_files entry with a newline", func(r *ingestRequest) { r.ChangedFiles = []string{"a.go\nb.go"} }, "changed_files"},
		{"repository_url on GitHub", func(r *ingestRequest) { r.RepositoryURL = "https://github.com/acme/shop" }, ""},
		{"repository_url on plain http", func(r *ingestRequest) { r.RepositoryURL = "http://git.internal:8080/acme/shop" }, ""},
		{"repository_url with a token", func(r *ingestRequest) {
			r.RepositoryURL = "https://gitlab-ci-token:glcbt-secret@gitlab.com/acme/shop.git"
		}, "repository_url"},
		{"repository_url with javascript", func(r *ingestRequest) { r.RepositoryURL = "javascript:alert(1)" }, "repository_url"},
		{"repository_url in capitals", func(r *ingestRequest) { r.RepositoryURL = "HTTPS://github.com/acme/shop" }, "repository_url"},
		{"repository_url relative", func(r *ingestRequest) { r.RepositoryURL = "/acme/shop" }, "repository_url"},
		{"repository_url without a host", func(r *ingestRequest) { r.RepositoryURL = "https:///acme" }, "repository_url"},
		{"repository_url with a space", func(r *ingestRequest) { r.RepositoryURL = "https://github.com/acme shop" }, "repository_url"},
		{"repository_url over the cap", func(r *ingestRequest) { r.RepositoryURL = "https://e.com/" + strings.Repeat("p", 2048) }, "repository_url"},
		{"ci_run_url on GitHub", func(r *ingestRequest) { r.CIRunURL = "https://github.com/acme/shop/actions/runs/42" }, ""},
		{"ci_run_url with a newline", func(r *ingestRequest) { r.CIRunURL = "https://e.com/\nx" }, "ci_run_url"},
		{"ci_run_url with ftp", func(r *ingestRequest) { r.CIRunURL = "ftp://e.com/run" }, "ci_run_url"},
		{"pull_request_number set", func(r *ingestRequest) { r.PullRequestNumber = 123 }, ""},
		{"pull_request_number negative", func(r *ingestRequest) { r.PullRequestNumber = -1 }, "pull_request_number"},
		{"pull_request_number over int32", func(r *ingestRequest) { r.PullRequestNumber = 1 << 31 }, "pull_request_number"},
		{"pull_request_title at the cap", func(r *ingestRequest) { r.PullRequestTitle = strings.Repeat("t", 512) }, ""},
		{"pull_request_title over the cap", func(r *ingestRequest) { r.PullRequestTitle = strings.Repeat("t", 513) }, "pull_request_title"},
		{"pull_request_title with a newline", func(r *ingestRequest) { r.PullRequestTitle = "fix\n## forged" }, "pull_request_title"},
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

// A refused repository URL must not echo the credential it carried.
func TestIngestRequest_URLWithTokenIsRefusedWithoutEchoingIt(t *testing.T) {
	field, problem := ingestRequest{
		Project: "p", Scanner: "s", RepositoryURL: "https://gitlab-ci-token:glcbt-secret@gitlab.com/acme/shop.git",
	}.invalidField()
	assert.Equal(t, "repository_url", field)
	assert.Equal(t, "must not contain a user name or password", problem)
	assert.NotContains(t, problem, "glcbt-secret")
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
		// The gate has no status filter; accepting the field and dropping it
		// gave a verdict computed without the filter the caller asked for.
		"gate_status": "open,reopened",
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
