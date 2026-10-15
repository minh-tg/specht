package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/minh-tg/specht/internal/usecase"
	"github.com/stretchr/testify/assert"
)

// The events route reads the type filter from the query. It used to hand the use case a nil
// filter, so ?type= was accepted and ignored.
func TestListFindingEvents_PassesTheTypeFilter(t *testing.T) {
	tests := []struct {
		name  string
		query string
		want  []string
	}{
		{"no filter", "", nil},
		{"repeated", "?type=analysis_changed&type=comment", []string{"analysis_changed", "comment"}},
		{"comma separated", "?type=analysis_changed,comment", []string{"analysis_changed", "comment"}},
		{"spaces and blanks are dropped", "?type=%20analysis_changed%20,,&type=", []string{"analysis_changed"}},
		{"only blanks means no filter", "?type=,", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			var gotLimit int32
			mock := &mockUsecases{
				getFindingEventsFn: func(_ context.Context, _ string, eventTypes []string, limit, _ int32) ([]usecase.FindingEvent, error) {
					got, gotLimit = eventTypes, limit
					return nil, nil
				},
			}
			req := httptest.NewRequest("GET", "/api/v1/findings/abc-123/events"+tc.query, nil)
			w := httptest.NewRecorder()
			testRouter(mock).ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Code)
			assert.Equal(t, tc.want, got)
			assert.Equal(t, int32(50), gotLimit, "the default page is unchanged")
		})
	}
}
