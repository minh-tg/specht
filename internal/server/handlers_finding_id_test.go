package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/minh-tg/specht/internal/port"
	"github.com/minh-tg/specht/internal/usecase"
)

// A malformed finding id on the events, evidence and signoff reads is the
// caller's mistake: 400, not 500 or 404.
func TestFindingIDReads_MalformedIDIs400(t *testing.T) {
	bad := fmt.Errorf("%w: invalid UUID length: 3", usecase.ErrInvalidFindingID)
	h := &Handler{usecase: &mockUsecases{
		getFindingEventsFn: func(context.Context, string, []string, int32, int32) ([]usecase.FindingEvent, error) {
			return nil, bad
		},
		listEvidenceFn: func(context.Context, string) ([]usecase.EvidenceResponse, error) { return nil, bad },
		getSignoffFn:   func(context.Context, string) (*usecase.SignoffResponse, error) { return nil, bad },
	}}
	for _, tc := range []struct {
		name, param string
		invoke      http.HandlerFunc
	}{
		{"events", "id", h.ListFindingEvents},
		{"evidence", "findingID", h.ListEvidence},
		{"signoff", "findingID", h.GetSignoff},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := addChiURLParam(authRequest("GET", "/api/v1/findings/abc/"+tc.name, ""), tc.param, "abc")
			w := httptest.NewRecorder()
			tc.invoke(w, req)
			requireAPIError(t, w, http.StatusBadRequest, "invalid_id")
		})
	}
}

// GetSignoff answers 404 only when the finding or its signoff is missing. A
// store failure used to be reported as "signoff not found" too.
func TestGetSignoff_OnlyMissingIs404(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		status int
		code   string
	}{
		{"no signoff", fmt.Errorf("get signoff: %w", port.ErrNotFound), http.StatusNotFound, "not_found"},
		{"no finding", usecase.ErrFindingNotFound, http.StatusNotFound, "not_found"},
		{"store failure", errors.New("connection reset"), http.StatusInternalServerError, "internal_error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &Handler{usecase: &mockUsecases{
				getSignoffFn: func(context.Context, string) (*usecase.SignoffResponse, error) { return nil, tc.err },
			}}
			req := addChiURLParam(authRequest("GET", "/api/v1/findings/f1/signoff", ""), "findingID", "f1")
			w := httptest.NewRecorder()
			h.GetSignoff(w, req)
			requireAPIError(t, w, tc.status, tc.code)
		})
	}
}
