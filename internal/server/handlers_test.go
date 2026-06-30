package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vulnserve/vulnserve/internal/usecase"
)

type mockUsecases struct {
	listProjectsFn func(ctx context.Context) ([]usecase.ProjectResponse, error)
	getProjectFn   func(ctx context.Context, slug string) (*usecase.ProjectResponse, error)
	listFindingsFn func(ctx context.Context, projectSlug string, severities, states []string, limit, offset int32) ([]usecase.FindingResponse, error)
	listReportsFn  func(ctx context.Context, projectSlug string, limit, offset int32) ([]usecase.ReportResponse, error)
	getReportFn    func(ctx context.Context, reportID pgtype.UUID) (*usecase.ReportResponse, error)
	ingestReportFn func(ctx context.Context, input usecase.IngestReportInput) (*usecase.IngestReportOutput, error)
}

func (m *mockUsecases) ListProjects(ctx context.Context) ([]usecase.ProjectResponse, error) {
	if m.listProjectsFn == nil {
		return nil, fmt.Errorf("unexpected call to ListProjects")
	}
	return m.listProjectsFn(ctx)
}

func (m *mockUsecases) GetProject(ctx context.Context, slug string) (*usecase.ProjectResponse, error) {
	if m.getProjectFn == nil {
		return nil, fmt.Errorf("unexpected call to GetProject")
	}
	return m.getProjectFn(ctx, slug)
}

func (m *mockUsecases) ListFindings(ctx context.Context, projectSlug string, severities, states []string, limit, offset int32) ([]usecase.FindingResponse, error) {
	if m.listFindingsFn == nil {
		return nil, fmt.Errorf("unexpected call to ListFindings")
	}
	return m.listFindingsFn(ctx, projectSlug, severities, states, limit, offset)
}

func (m *mockUsecases) ListReports(ctx context.Context, projectSlug string, limit, offset int32) ([]usecase.ReportResponse, error) {
	if m.listReportsFn == nil {
		return nil, fmt.Errorf("unexpected call to ListReports")
	}
	return m.listReportsFn(ctx, projectSlug, limit, offset)
}

func (m *mockUsecases) GetReport(ctx context.Context, reportID pgtype.UUID) (*usecase.ReportResponse, error) {
	if m.getReportFn == nil {
		return nil, fmt.Errorf("unexpected call to GetReport")
	}
	return m.getReportFn(ctx, reportID)
}

func (m *mockUsecases) IngestReport(ctx context.Context, input usecase.IngestReportInput) (*usecase.IngestReportOutput, error) {
	if m.ingestReportFn == nil {
		return nil, fmt.Errorf("unexpected call to IngestReport")
	}
	return m.ingestReportFn(ctx, input)
}

var now = time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)

func sampleProjects() []usecase.ProjectResponse {
	return []usecase.ProjectResponse{
		{ID: "proj-1", Slug: "my-app", Name: "My App", Description: strPtr("example"), CreatedAt: now, UpdatedAt: now},
	}
}

func sampleFindings() []usecase.FindingResponse {
	return []usecase.FindingResponse{
		{ID: "find-1", ProjectID: "proj-1", FindingKind: "sca", Fingerprint: "fp1", CurrentTitle: "CVE-2026-1234", CurrentSeverity: "high", State: "open", TriageStatus: "untriaged", FirstSeenAt: now, LastSeenAt: now, CreatedAt: now, UpdatedAt: now},
	}
}

func sampleReports() []usecase.ReportResponse {
	return []usecase.ReportResponse{
		{ID: "rep-1", ProjectID: "proj-1", ToolName: "trivy", ScanType: "image", Status: "completed", TotalFindings: int32Ptr(5), CreatedAt: now, CompletedAt: &now},
	}
}

func strPtr(s string) *string { return &s }
func int32Ptr(i int32) *int32 { return &i }

func TestHealthHandler(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/v1/health", nil)
	w := httptest.NewRecorder()

	router := NewRouter(RouterConfig{Usecases: nil})
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var body map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &body)
	require.NoError(t, err)
	assert.Equal(t, "ok", body["status"])
}

func TestRespondJSON(t *testing.T) {
	w := httptest.NewRecorder()
	respondJSON(w, http.StatusCreated, map[string]string{"hello": "world"})

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var body map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &body)
	require.NoError(t, err)
	assert.Equal(t, "world", body["hello"])
}

func TestRespondError(t *testing.T) {
	w := httptest.NewRecorder()
	respondError(w, http.StatusBadRequest, "missing_field", "project is required")

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "missing_field", resp.Error.Code)
	assert.Equal(t, "project is required", resp.Error.Message)
}

func TestIngestReport_InvalidJSON(t *testing.T) {
	handler := &Handler{uc: nil}
	body := strings.NewReader(`not json`)
	req := httptest.NewRequest("POST", "/api/v1/reports", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.IngestReport(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "invalid_json", resp.Error.Code)
}

func TestIngestReport_MissingFields(t *testing.T) {
	handler := &Handler{uc: nil}

	tests := []struct {
		name       string
		body       string
		wantStatus int
		wantCode   string
	}{
		{"missing project", `{"scanner":"trivy","raw_data":{}}`, http.StatusBadRequest, "missing_field"},
		{"missing scanner", `{"project":"test","raw_data":{}}`, http.StatusBadRequest, "missing_field"},
		{"missing raw_data", `{"project":"test","scanner":"trivy"}`, http.StatusBadRequest, "missing_field"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/api/v1/reports", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			handler.IngestReport(w, req)

			assert.Equal(t, tt.wantStatus, w.Code)

			var resp struct {
				Error struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			}
			err := json.Unmarshal(w.Body.Bytes(), &resp)
			require.NoError(t, err)
			assert.Equal(t, tt.wantCode, resp.Error.Code)
		})
	}
}

func testRouter(mock *mockUsecases) http.Handler {
	r := chi.NewRouter()
	h := NewHandler(mock)
	r.Get("/api/v1/projects", h.ListProjects)
	r.Get("/api/v1/projects/{slug}", h.GetProject)
	r.Get("/api/v1/projects/{slug}/findings", h.ListFindings)
	r.Get("/api/v1/projects/{slug}/reports", h.ListReports)
	r.Get("/api/v1/reports/{id}", h.GetReport)
	return r
}

func TestListProjects_Success(t *testing.T) {
	mock := &mockUsecases{
		listProjectsFn: func(ctx context.Context) ([]usecase.ProjectResponse, error) {
			return sampleProjects(), nil
		},
	}
	router := testRouter(mock)
	req := httptest.NewRequest("GET", "/api/v1/projects", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp []usecase.ProjectResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Len(t, resp, 1)
	assert.Equal(t, "my-app", resp[0].Slug)
}

func TestListProjects_Error(t *testing.T) {
	mock := &mockUsecases{
		listProjectsFn: func(ctx context.Context) ([]usecase.ProjectResponse, error) {
			return nil, fmt.Errorf("db error")
		},
	}
	h := &Handler{uc: mock}
	req := httptest.NewRequest("GET", "/api/v1/projects", nil)
	w := httptest.NewRecorder()
	h.ListProjects(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	var resp struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "internal_error", resp.Error.Code)
}

func TestGetProject_Success(t *testing.T) {
	mock := &mockUsecases{
		getProjectFn: func(ctx context.Context, slug string) (*usecase.ProjectResponse, error) {
			assert.Equal(t, "my-app", slug)
			return &sampleProjects()[0], nil
		},
	}
	router := testRouter(mock)
	req := httptest.NewRequest("GET", "/api/v1/projects/my-app", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp usecase.ProjectResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "my-app", resp.Slug)
}

func TestGetProject_NotFound(t *testing.T) {
	mock := &mockUsecases{
		getProjectFn: func(ctx context.Context, slug string) (*usecase.ProjectResponse, error) {
			return nil, fmt.Errorf("not found")
		},
	}
	router := testRouter(mock)
	req := httptest.NewRequest("GET", "/api/v1/projects/nonexistent", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestListFindings_Success(t *testing.T) {
	mock := &mockUsecases{
		listFindingsFn: func(ctx context.Context, projectSlug string, severities, states []string, limit, offset int32) ([]usecase.FindingResponse, error) {
			assert.Equal(t, "my-app", projectSlug)
			assert.Equal(t, int32(20), limit)
			assert.Equal(t, int32(0), offset)
			return sampleFindings(), nil
		},
	}
	router := testRouter(mock)
	req := httptest.NewRequest("GET", "/api/v1/projects/my-app/findings", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp []usecase.FindingResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Len(t, resp, 1)
	assert.Equal(t, "sca", resp[0].FindingKind)
}

func TestListFindings_WithFilters(t *testing.T) {
	mock := &mockUsecases{
		listFindingsFn: func(ctx context.Context, projectSlug string, severities, states []string, limit, offset int32) ([]usecase.FindingResponse, error) {
			assert.Equal(t, []string{"high", "critical"}, severities)
			assert.Equal(t, []string{"open"}, states)
			assert.Equal(t, int32(50), limit)
			assert.Equal(t, int32(10), offset)
			return sampleFindings(), nil
		},
	}
	router := testRouter(mock)
	req := httptest.NewRequest("GET", "/api/v1/projects/my-app/findings?severity=high,critical&status=open&limit=50&offset=10", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestListFindings_NotFound(t *testing.T) {
	mock := &mockUsecases{
		listFindingsFn: func(ctx context.Context, projectSlug string, severities, states []string, limit, offset int32) ([]usecase.FindingResponse, error) {
			return nil, fmt.Errorf("not found")
		},
	}
	router := testRouter(mock)
	req := httptest.NewRequest("GET", "/api/v1/projects/nonexistent/findings", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestListReports_Success(t *testing.T) {
	mock := &mockUsecases{
		listReportsFn: func(ctx context.Context, projectSlug string, limit, offset int32) ([]usecase.ReportResponse, error) {
			assert.Equal(t, "my-app", projectSlug)
			assert.Equal(t, int32(20), limit)
			assert.Equal(t, int32(0), offset)
			return sampleReports(), nil
		},
	}
	router := testRouter(mock)
	req := httptest.NewRequest("GET", "/api/v1/projects/my-app/reports", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp []usecase.ReportResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Len(t, resp, 1)
	assert.Equal(t, "trivy", resp[0].ToolName)
}

func TestListReports_NotFound(t *testing.T) {
	mock := &mockUsecases{
		listReportsFn: func(ctx context.Context, projectSlug string, limit, offset int32) ([]usecase.ReportResponse, error) {
			return nil, fmt.Errorf("not found")
		},
	}
	router := testRouter(mock)
	req := httptest.NewRequest("GET", "/api/v1/projects/nonexistent/reports", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestGetReport_Success(t *testing.T) {
	mock := &mockUsecases{
		getReportFn: func(ctx context.Context, id pgtype.UUID) (*usecase.ReportResponse, error) {
			return &sampleReports()[0], nil
		},
	}
	router := testRouter(mock)
	req := httptest.NewRequest("GET", "/api/v1/reports/550e8400-e29b-41d4-a716-446655440000", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp usecase.ReportResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "trivy", resp.ToolName)
}

func TestGetReport_NotFound(t *testing.T) {
	mock := &mockUsecases{
		getReportFn: func(ctx context.Context, id pgtype.UUID) (*usecase.ReportResponse, error) {
			return nil, fmt.Errorf("not found")
		},
	}
	router := testRouter(mock)
	req := httptest.NewRequest("GET", "/api/v1/reports/550e8400-e29b-41d4-a716-446655440000", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestGetReport_InvalidID(t *testing.T) {
	router := testRouter(nil)
	req := httptest.NewRequest("GET", "/api/v1/reports/not-a-uuid", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "invalid_id", resp.Error.Code)
}

func TestNewRouterRoutes(t *testing.T) {
	mock := &mockUsecases{
		listProjectsFn: func(ctx context.Context) ([]usecase.ProjectResponse, error) { return nil, nil },
		getProjectFn:   func(ctx context.Context, slug string) (*usecase.ProjectResponse, error) { return nil, nil },
		listFindingsFn: func(ctx context.Context, projectSlug string, severities, states []string, limit, offset int32) ([]usecase.FindingResponse, error) { return nil, nil },
		listReportsFn:  func(ctx context.Context, projectSlug string, limit, offset int32) ([]usecase.ReportResponse, error) { return nil, nil },
		getReportFn:    func(ctx context.Context, id pgtype.UUID) (*usecase.ReportResponse, error) { return nil, nil },
	}
	router := NewRouter(RouterConfig{Usecases: mock})
	require.NotNil(t, router)

	t.Run("health endpoint exists", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/health", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("reports POST endpoint exists", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/reports", strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.NotEqual(t, http.StatusNotFound, w.Code)
	})

	t.Run("projects list endpoint exists", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/projects", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.NotEqual(t, http.StatusNotFound, w.Code)
	})

	t.Run("project detail endpoint exists", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/projects/my-app", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.NotEqual(t, http.StatusNotFound, w.Code)
	})

	t.Run("findings list endpoint exists", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/projects/my-app/findings", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.NotEqual(t, http.StatusNotFound, w.Code)
	})

	t.Run("reports list endpoint exists", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/projects/my-app/reports", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.NotEqual(t, http.StatusNotFound, w.Code)
	})

	t.Run("report detail endpoint exists", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/reports/550e8400-e29b-41d4-a716-446655440000", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.NotEqual(t, http.StatusNotFound, w.Code)
	})

	t.Run("unknown route returns 404", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/nonexistent", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}
