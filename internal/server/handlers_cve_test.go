package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/cvedetail"
	"github.com/minh-tg/specht/internal/usecase"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func (m *mockUsecases) GetFindingCVE(ctx context.Context, findingID string) (*usecase.CVEDetailResponse, error) {
	if m.getFindingCVEFn == nil {
		return nil, fmt.Errorf("unexpected call to GetFindingCVE")
	}
	return m.getFindingCVEFn(ctx, findingID)
}

const cveHandlerFindingID = "00000000-0000-0000-0000-000000000021"

// cveRouter serves the production routes over mock, with an API key that
// belongs to project-1 and carries scopes.
func cveRouter(mock *mockUsecases, scopes ...string) http.Handler {
	return NewRouter(RouterConfig{
		Usecases: mock,
		JWTAuth:  testJWTAuth,
		APIKeyLookup: func(ctx context.Context, keyHash string) (string, string, []string, time.Time, error) {
			return "key-1", "00000000-0000-0000-0000-000000000001", scopes, time.Time{}, nil
		},
	})
}

func getCVE(t *testing.T, h http.Handler, id, bearer string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/findings/"+id+"/cve", nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func TestGetFindingCVE_ReturnsTheContract(t *testing.T) {
	score := 10.0
	sev := "critical"
	observed := time.Date(2026, 10, 14, 8, 0, 0, 0, time.UTC)
	rid := "5d000000-0000-0000-0000-000000000001"
	var gotID string
	mock := &mockUsecases{getFindingCVEFn: func(ctx context.Context, id string) (*usecase.CVEDetailResponse, error) {
		gotID = id
		return &usecase.CVEDetailResponse{
			CVEID: "CVE-2024-3094",
			CVSS: []usecase.CVECVSS{{
				Version: "3.1", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
				BaseScore: &score, ReportedScore: &score, Severity: &sev, Valid: true,
				Metrics:    []cvedetail.Metric{{Group: "base", Key: "AV", Value: "N"}},
				Provenance: usecase.CVEProvenance{Kind: "scan_report", Tool: "grype", ReportID: &rid, ObservedAt: &observed, Detail: "nvd:primary"},
			}},
			CWEs:       []usecase.CVECWE{},
			References: []usecase.CVEReference{},
			Providers:  []usecase.CVEProviderState{{Name: "nvd", Status: "skipped"}},
		}, nil
	}}
	w := getCVE(t, cveRouter(mock), cveHandlerFindingID, testToken(t))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Equal(t, cveHandlerFindingID, gotID)
	assert.JSONEq(t, `{
		"cve_id": "CVE-2024-3094",
		"pending": false,
		"cvss": [{
			"version": "3.1",
			"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
			"base_score": 10, "reported_score": 10, "severity": "critical", "valid": true,
			"metrics": [{"group": "base", "key": "AV", "value": "N"}],
			"provenance": {"kind": "scan_report", "tool": "grype", "report_id": "5d000000-0000-0000-0000-000000000001", "observed_at": "2026-10-14T08:00:00Z", "detail": "nvd:primary"}
		}],
		"epss": null, "kev": null, "cwes": [], "published_at": null, "modified_at": null, "references": [],
		"providers": [{"name": "nvd", "status": "skipped"}]
	}`, w.Body.String())
}

func TestGetFindingCVE_Errors(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		status int
		code   string
	}{
		{"not a cve", usecase.ErrNotCVE, http.StatusNotFound, "not_cve"},
		{"missing finding", fmt.Errorf("get finding: %w", usecase.ErrFindingNotFound), http.StatusNotFound, "not_found"},
		{"no project access", usecase.ErrProjectAccessDenied, http.StatusForbidden, "project_access_denied"},
		{"internal", errors.New("pq: relation does not exist"), http.StatusInternalServerError, "cve_detail_failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mock := &mockUsecases{getFindingCVEFn: func(context.Context, string) (*usecase.CVEDetailResponse, error) { return nil, tc.err }}
			w := getCVE(t, cveRouter(mock), cveHandlerFindingID, testToken(t))
			require.Equal(t, tc.status, w.Code, w.Body.String())
			var body struct {
				Error struct {
					Code string `json:"code"`
				} `json:"error"`
			}
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
			assert.Equal(t, tc.code, body.Error.Code)
			assert.NotContains(t, w.Body.String(), "pq:", "store errors never reach the client")
		})
	}
}

func TestGetFindingCVE_RejectsMalformedID(t *testing.T) {
	mock := &mockUsecases{}
	w := getCVE(t, cveRouter(mock), "not-a-uuid", testToken(t))
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetFindingCVE_Auth(t *testing.T) {
	called := false
	mock := &mockUsecases{getFindingCVEFn: func(ctx context.Context, id string) (*usecase.CVEDetailResponse, error) {
		called = true
		return &usecase.CVEDetailResponse{CVEID: "CVE-2024-3094"}, nil
	}}

	w := getCVE(t, cveRouter(mock), cveHandlerFindingID, "")
	assert.Equal(t, http.StatusUnauthorized, w.Code, "anonymous callers are refused")
	assert.False(t, called)

	w = getCVE(t, cveRouter(mock, auth.ScopeIngest), cveHandlerFindingID, "vuln_ingest_only_key")
	assert.Equal(t, http.StatusForbidden, w.Code, "an ingest-only key cannot read findings")
	assert.False(t, called)

	w = getCVE(t, cveRouter(mock, auth.ScopeRead), cveHandlerFindingID, "vuln_read_key")
	assert.Equal(t, http.StatusOK, w.Code, "a read key may read; project matching is the usecase's job")
	assert.True(t, called)

	called = false
	w = getCVE(t, cveRouter(mock), cveHandlerFindingID, makeTestToken(t, auth.RoleViewer))
	assert.Equal(t, http.StatusOK, w.Code, "a session viewer reaches the usecase, which checks membership")
	assert.True(t, called)
}
