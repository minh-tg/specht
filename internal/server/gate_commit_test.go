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

func TestGateStatus_IntroducedAtCommit(t *testing.T) {
	var gotCommit string
	mock := &mockUsecases{
		getCommitGateFn: func(_ context.Context, _ string, _ int16, commit string) (*usecase.GateStatusOutput, error) {
			gotCommit = commit
			return &usecase.GateStatusOutput{ThresholdBreached: true, BlockingCount: 9, BlockedBy: []string{"f1"}}, nil
		},
	}
	w := httptest.NewRecorder()
	testRouter(mock).ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		"/api/v1/projects/my-app/gate?introduced_only=true&commit=9f8e7d6c5b4a", nil))

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Equal(t, "9f8e7d6c5b4a", gotCommit)
	var out usecase.GateStatusOutput
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &out))
	assert.EqualValues(t, 9, out.BlockingCount)
}

func TestGateStatus_IntroducedAtCommitRefusals(t *testing.T) {
	cases := map[string]struct {
		query  string
		err    error
		status int
		code   string
	}{
		"report and commit together": {
			query: "introduced_only=1&report_id=r1&commit=abc", status: http.StatusBadRequest, code: "conflicting_scope",
		},
		"commit with a slash": {
			query: "introduced_only=1&commit=abc%2F..", status: http.StatusBadRequest, code: "invalid_commit",
		},
		"commit longer than any sha": {
			query: "introduced_only=1&commit=" + strings.Repeat("a", 65), status: http.StatusBadRequest, code: "invalid_commit",
		},
		"no completed scan of the commit": {
			query: "introduced_only=1&commit=abc", err: usecase.ErrNoReportForCommit, status: http.StatusNotFound, code: "no_report_for_commit",
		},
		"not a member": {
			query: "introduced_only=1&commit=abc", err: usecase.ErrProjectAccessDenied, status: http.StatusForbidden, code: "project_access_denied",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			mock := &mockUsecases{
				getCommitGateFn: func(context.Context, string, int16, string) (*usecase.GateStatusOutput, error) {
					if tc.err == nil {
						t.Fatal("a refused request must not reach the evaluation")
					}
					return nil, tc.err
				},
			}
			w := httptest.NewRecorder()
			testRouter(mock).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/projects/my-app/gate?"+tc.query, nil))

			assert.Equal(t, tc.status, w.Code, w.Body.String())
			assert.Contains(t, w.Body.String(), `"`+tc.code+`"`)
		})
	}
}
