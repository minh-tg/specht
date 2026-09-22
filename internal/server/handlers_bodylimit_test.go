package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/minh-tg/specht/internal/usecase"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// requireAPIError asserts the response is an apiError with the given status,
// code, and (when non-empty) message.
func requireAPIError(t *testing.T, w *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	assert.Equal(t, status, w.Code, "status")
	var resp struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp), "response must be a JSON apiError")
	assert.Equal(t, code, resp.Error.Code, "code")
}

// ingestBody builds a valid ingest payload whose raw_data is a JSON string of
// rawLen bytes.
func ingestBody(rawLen int) *strings.Reader {
	var b strings.Builder
	b.Grow(rawLen + 128)
	b.WriteString(`{"project":"my-app","scanner":"trivy","raw_data":"`)
	b.WriteString(strings.Repeat("a", rawLen))
	b.WriteString(`"}`)
	return strings.NewReader(b.String())
}

// bulkBody builds a valid bulk-triage payload carrying n finding ids.
func bulkBody(n int) string {
	var b strings.Builder
	b.Grow(n*10 + 96)
	b.WriteString(`{"finding_ids":[`)
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `"f-%05d"`, i)
	}
	b.WriteString(`],"analysis_state":"false_positive","reason":"bulk test"}`)
	return b.String()
}

// M1: ingest raw_data is scanner-supplied and unbounded; an oversized payload
// must be rejected before the use case sees it. With the Content-Length the
// client declares, the cap is enforceable up front.
func TestIngestReport_BodyTooLarge(t *testing.T) {
	var called bool
	mock := &mockUsecases{
		ingestReportFn: func(ctx context.Context, input usecase.IngestReportInput) (*usecase.IngestReportOutput, error) {
			called = true
			return &usecase.IngestReportOutput{ReportID: "rep-1", TotalFindings: 1}, nil
		},
	}
	router := NewRouter(RouterConfig{Usecases: mock, JWTAuth: testJWTAuth})
	req := httptest.NewRequest("POST", "/api/v1/reports", ingestBody(26<<20))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+testToken(t))
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	requireAPIError(t, w, http.StatusRequestEntityTooLarge, "body_too_large")
	assert.False(t, called, "ingest use case must not run for an oversized body")
}

// Same rejection must hold when the client sends no Content-Length (chunked
// transfer), so the limit relies on MaxBytesReader rather than the header.
func TestIngestReport_BodyTooLarge_NoContentLength(t *testing.T) {
	var called bool
	mock := &mockUsecases{
		ingestReportFn: func(ctx context.Context, input usecase.IngestReportInput) (*usecase.IngestReportOutput, error) {
			called = true
			return &usecase.IngestReportOutput{ReportID: "rep-1", TotalFindings: 1}, nil
		},
	}
	router := NewRouter(RouterConfig{Usecases: mock, JWTAuth: testJWTAuth})
	req := httptest.NewRequest("POST", "/api/v1/reports", ingestBody(26<<20))
	req.ContentLength = -1 // chunked: no declared length
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+testToken(t))
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	requireAPIError(t, w, http.StatusRequestEntityTooLarge, "body_too_large")
	assert.False(t, called, "ingest use case must not run for an oversized body")
}

// Large-but-legitimate reports must still get through: the ingest cap sits in
// the 10-25 MiB band, so a 5 MiB payload is well inside it.
func TestIngestReport_LargePayloadAccepted(t *testing.T) {
	var got usecase.IngestReportInput
	mock := &mockUsecases{
		ingestReportFn: func(ctx context.Context, input usecase.IngestReportInput) (*usecase.IngestReportOutput, error) {
			got = input
			return &usecase.IngestReportOutput{ReportID: "rep-1", TotalFindings: 1}, nil
		},
	}
	router := NewRouter(RouterConfig{Usecases: mock, JWTAuth: testJWTAuth})
	req := httptest.NewRequest("POST", "/api/v1/reports", ingestBody(5<<20))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+testToken(t))
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.Len(t, got.RawData, 5<<20+2, "raw_data must round-trip intact")
}

// M1: auth endpoints are public (no auth middleware in front), so their body
// cap is the only defence against unbounded credential fields.
func TestLogin_BodyTooLarge(t *testing.T) {
	var called bool
	mock := &mockUsecases{
		loginFn: func(ctx context.Context, email, password string) (*usecase.AuthResponse, error) {
			called = true
			return &usecase.AuthResponse{Token: "tok", UserID: "u1", Email: email}, nil
		},
	}
	router := NewRouter(RouterConfig{Usecases: mock, JWTAuth: testJWTAuth})
	body := `{"email":"a@b.com","password":"` + strings.Repeat("a", 2<<20) + `"}`
	req := httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	requireAPIError(t, w, http.StatusRequestEntityTooLarge, "body_too_large")
	assert.False(t, called, "login use case must not run for an oversized body")
}

// M1: bulk triage fans out over finding_ids; an unbounded array would let a
// request drive unbounded per-id work.
func TestBulkTriage_TooManyFindingIDs(t *testing.T) {
	var called bool
	mock := &mockUsecases{
		bulkTriageFn: func(ctx context.Context, input usecase.BulkTriageInput) ([]usecase.TriageOutput, error) {
			called = true
			return nil, nil
		},
	}
	router := testRouter(mock)
	req := authRequest("POST", "/api/v1/findings/bulk-analysis", bulkBody(1001))
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	requireAPIError(t, w, http.StatusBadRequest, "too_many_ids")
	assert.False(t, called, "bulk triage use case must not run past the id cap")
}

// Exactly 1000 ids is the documented boundary and must still be accepted.
func TestBulkTriage_MaxFindingIDsAccepted(t *testing.T) {
	var got usecase.BulkTriageInput
	mock := &mockUsecases{
		bulkTriageFn: func(ctx context.Context, input usecase.BulkTriageInput) ([]usecase.TriageOutput, error) {
			got = input
			return nil, nil
		},
	}
	router := testRouter(mock)
	req := authRequest("POST", "/api/v1/findings/bulk-analysis", bulkBody(1000))
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Len(t, got.FindingIDs, 1000)
}

// M1: AddProjectMember must enforce the standard JSON body cap as well.
func TestAddProjectMember_BodyTooLarge(t *testing.T) {
	var called bool
	mock := &mockUsecases{
		addProjectMemberFn: func(ctx context.Context, projectSlug, userID, role string) (*usecase.ProjectMemberResponse, error) {
			called = true
			return &usecase.ProjectMemberResponse{ProjectID: "p1", UserID: userID, Role: role}, nil
		},
		listProjectMembersFn: func(ctx context.Context, projectSlug string) ([]usecase.ProjectMemberResponse, error) {
			return nil, nil
		},
		isProjectMemberFn: func(ctx context.Context, projectID, userID string) (bool, error) {
			return true, nil
		},
		getProjectFn: func(ctx context.Context, slug string) (*usecase.ProjectResponse, error) {
			return &usecase.ProjectResponse{ID: "p1", Slug: slug}, nil
		},
	}
	router := testRouter(mock)
	body := `{"user_id":"` + strings.Repeat("a", 2<<20) + `","role":"viewer"}`
	req := authRequest("POST", "/api/v1/projects/my-app/members", body)
	req = addChiURLParam(req, "slug", "my-app")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	requireAPIError(t, w, http.StatusRequestEntityTooLarge, "body_too_large")
	assert.False(t, called, "add project member use case must not run for an oversized body")
}
