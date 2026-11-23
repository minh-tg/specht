package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/usecase"
)

func TestNeedsYou_Success(t *testing.T) {
	h := &Handler{usecase: &mockUsecases{
		getNeedsYouFn: func(context.Context) (*usecase.NeedsYouResponse, error) {
			return &usecase.NeedsYouResponse{
				Count: 1, AssignedFindings: 1,
				Items: []usecase.NeedsYouItem{{
					Kind: usecase.NeedsYouFindingAssigned, ProjectSlug: "my-app", ProjectName: "My app",
					Title: "lodash", Link: "/my-app/findings/f1",
				}},
			}, nil
		},
	}}
	w := httptest.NewRecorder()
	h.NeedsYou(w, httptest.NewRequest(http.MethodGet, "/api/v1/me/needs-you", nil))

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"), "what waits on a person is never cached")
	var resp struct {
		Count int `json:"count"`
		Items []struct {
			Kind string `json:"kind"`
			Link string `json:"link"`
		} `json:"items"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, 1, resp.Count)
	require.Len(t, resp.Items, 1)
	assert.Equal(t, "finding_assigned", resp.Items[0].Kind)
	assert.Equal(t, "/my-app/findings/f1", resp.Items[0].Link)
}

func TestNeedsYou_Errors(t *testing.T) {
	for name, tc := range map[string]struct {
		err  error
		code int
		want string
	}{
		"an API key": {err: usecase.ErrProjectAccessDenied, code: http.StatusForbidden, want: "project_access_denied"},
		"store down": {err: fmt.Errorf("db down"), code: http.StatusInternalServerError, want: "internal_error"},
	} {
		t.Run(name, func(t *testing.T) {
			h := &Handler{usecase: &mockUsecases{
				getNeedsYouFn: func(context.Context) (*usecase.NeedsYouResponse, error) { return nil, tc.err },
			}}
			w := httptest.NewRecorder()
			h.NeedsYou(w, httptest.NewRequest(http.MethodGet, "/api/v1/me/needs-you", nil))
			assert.Equal(t, tc.code, w.Code)
			assert.Contains(t, w.Body.String(), tc.want)
			assert.NotContains(t, w.Body.String(), "db down")
		})
	}
}
