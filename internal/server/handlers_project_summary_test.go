package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/usecase"
)

func TestListProjectSummaries_Success(t *testing.T) {
	mock := &mockUsecases{
		listProjectSummariesFn: func(context.Context) ([]usecase.ProjectSummary, error) {
			return []usecase.ProjectSummary{{
				Slug:  "my-app",
				Gate:  &usecase.GateStatusOutput{ThresholdBreached: true, BlockingCount: 1, BlockedBy: []string{"f1"}, WaivedFindingIDs: []string{}},
				Stats: &usecase.ProjectStats{TotalFindings: 3, BySeverity: []usecase.SeverityCount{}, ByAnalysisState: []usecase.AnalysisStateCount{}},
			}}, nil
		},
	}
	h := &Handler{usecase: mock}
	w := httptest.NewRecorder()
	h.ListProjectSummaries(w, httptest.NewRequest(http.MethodGet, "/api/v1/project-summaries", nil))

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var resp []struct {
		Slug  string                   `json:"slug"`
		Gate  usecase.GateStatusOutput `json:"gate"`
		Stats usecase.ProjectStats     `json:"stats"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.Len(t, resp, 1)
	assert.Equal(t, "my-app", resp[0].Slug)
	assert.Equal(t, []string{"f1"}, resp[0].Gate.BlockedBy)
	assert.Equal(t, int32(3), resp[0].Stats.TotalFindings)
}

func TestListProjectSummaries_Errors(t *testing.T) {
	for name, tc := range map[string]struct {
		err  error
		code int
		want string
	}{
		"access denied": {err: usecase.ErrProjectAccessDenied, code: http.StatusForbidden, want: "project_access_denied"},
		"store failure": {err: fmt.Errorf("db down"), code: http.StatusInternalServerError, want: "internal_error"},
	} {
		t.Run(name, func(t *testing.T) {
			mock := &mockUsecases{
				listProjectSummariesFn: func(context.Context) ([]usecase.ProjectSummary, error) { return nil, tc.err },
			}
			h := &Handler{usecase: mock}
			w := httptest.NewRecorder()
			h.ListProjectSummaries(w, httptest.NewRequest(http.MethodGet, "/api/v1/project-summaries", nil))
			assert.Equal(t, tc.code, w.Code)
			assert.Contains(t, w.Body.String(), tc.want)
			assert.NotContains(t, w.Body.String(), "db down", "the store error stays in the log")
		})
	}
}

// The route carries the read scope, like the per-project gate and stats
// routes: an ingest-only key never reaches the use case.
func TestRoutes_ProjectSummariesNeedReadScope(t *testing.T) {
	const projectID = "00000000-0000-0000-0000-000000000001"
	request := func(scopes ...string) (*httptest.ResponseRecorder, bool) {
		called := false
		mock := &mockUsecases{
			listProjectSummariesFn: func(context.Context) ([]usecase.ProjectSummary, error) {
				called = true
				return []usecase.ProjectSummary{}, nil
			},
		}
		router := NewRouter(RouterConfig{
			Usecases: mock,
			JWTAuth:  testJWTAuth,
			APIKeyLookup: func(context.Context, string) (string, string, []string, time.Time, error) {
				return "key-1", projectID, scopes, time.Time{}, nil
			},
		})
		req := httptest.NewRequest(http.MethodGet, "/api/v1/project-summaries", nil)
		req.Header.Set("Authorization", "Bearer vuln_summary_key")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w, called
	}

	w, called := request(auth.ScopeIngest)
	assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	assert.False(t, called, "an ingest-only key must not reach the use case")

	w, called = request(auth.ScopeRead)
	assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.True(t, called)
}
