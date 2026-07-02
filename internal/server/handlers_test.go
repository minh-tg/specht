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
	"github.com/xMinhx/specht/internal/auth"
	"github.com/stretchr/testify/require"
	"github.com/xMinhx/specht/internal/usecase"
)

type mockUsecases struct {
	listProjectsFn func(ctx context.Context) ([]usecase.ProjectResponse, error)
	getProjectFn   func(ctx context.Context, slug string) (*usecase.ProjectResponse, error)
	listFindingsFn func(ctx context.Context, projectSlug string, severities, states []string, limit, offset int32) ([]usecase.FindingResponse, error)
	listReportsFn  func(ctx context.Context, projectSlug string, limit, offset int32) ([]usecase.ReportResponse, error)
	getReportFn    func(ctx context.Context, reportID pgtype.UUID) (*usecase.ReportResponse, error)
	ingestReportFn func(ctx context.Context, input usecase.IngestReportInput) (*usecase.IngestReportOutput, error)
	registerFn     func(ctx context.Context, email, password string) (*usecase.AuthResponse, error)
	loginFn        func(ctx context.Context, email, password string) (*usecase.AuthResponse, error)
	createAPIKeyFn func(ctx context.Context, projectSlug, name string) (*usecase.APIKeyResponse, error)
	listAPIKeysFn  func(ctx context.Context, projectSlug string) ([]usecase.APIKeyResponse, error)
	revokeAPIKeyFn func(ctx context.Context, projectSlug, keyID string) error
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

func (m *mockUsecases) Register(ctx context.Context, email, password string) (*usecase.AuthResponse, error) {
	if m.registerFn == nil {
		return nil, fmt.Errorf("unexpected call to Register")
	}
	return m.registerFn(ctx, email, password)
}

func (m *mockUsecases) Login(ctx context.Context, email, password string) (*usecase.AuthResponse, error) {
	if m.loginFn == nil {
		return nil, fmt.Errorf("unexpected call to Login")
	}
	return m.loginFn(ctx, email, password)
}

func (m *mockUsecases) CreateAPIKey(ctx context.Context, projectSlug, name string) (*usecase.APIKeyResponse, error) {
	if m.createAPIKeyFn == nil {
		return nil, fmt.Errorf("unexpected call to CreateAPIKey")
	}
	return m.createAPIKeyFn(ctx, projectSlug, name)
}

func (m *mockUsecases) ListAPIKeys(ctx context.Context, projectSlug string) ([]usecase.APIKeyResponse, error) {
	if m.listAPIKeysFn == nil {
		return nil, fmt.Errorf("unexpected call to ListAPIKeys")
	}
	return m.listAPIKeysFn(ctx, projectSlug)
}

func (m *mockUsecases) RevokeAPIKey(ctx context.Context, projectSlug, keyID string) error {
	if m.revokeAPIKeyFn == nil {
		return fmt.Errorf("unexpected call to RevokeAPIKey")
	}
	return m.revokeAPIKeyFn(ctx, projectSlug, keyID)
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

	router := NewRouter(RouterConfig{Usecases: nil, JWTAuth: testJWTAuth})
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

func TestIngestReport_Success(t *testing.T) {
	mock := &mockUsecases{
		ingestReportFn: func(ctx context.Context, input usecase.IngestReportInput) (*usecase.IngestReportOutput, error) {
			return &usecase.IngestReportOutput{ReportID: "rep-1", TotalFindings: 3, ThresholdBreached: true}, nil
		},
	}
	router := testRouter(mock)
	body := strings.NewReader(`{"project":"my-app","scanner":"trivy","raw_data":{"image":"myapp:latest"}}`)
	req := httptest.NewRequest("POST", "/api/v1/reports", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	var resp struct {
		ReportID          string `json:"report_id"`
		TotalFindings     int    `json:"total_findings"`
		ThresholdBreached bool   `json:"threshold_breached"`
	}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "rep-1", resp.ReportID)
	assert.Equal(t, 3, resp.TotalFindings)
	assert.True(t, resp.ThresholdBreached)
}

func testRouter(mock *mockUsecases) http.Handler {
	r := chi.NewRouter()
	h := NewHandler(mock)
	r.Get("/api/v1/projects", h.ListProjects)
	r.Get("/api/v1/projects/{slug}", h.GetProject)
	r.Get("/api/v1/projects/{slug}/findings", h.ListFindings)
	r.Get("/api/v1/projects/{slug}/reports", h.ListReports)
	r.Get("/api/v1/reports/{id}", h.GetReport)
	r.Post("/api/v1/reports", h.IngestReport)
	r.Post("/api/v1/auth/register", h.Register)
	r.Post("/api/v1/auth/login", h.Login)
	r.Post("/api/v1/auth/apikeys", h.CreateAPIKey)
	r.Get("/api/v1/auth/apikeys", h.ListAPIKeys)
	r.Delete("/api/v1/auth/apikeys/{id}", h.RevokeAPIKey)
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

var corsMock = &mockUsecases{}

const testJWTSecret = "test-secret-not-for-production-use"

var testJWTAuth = func() *auth.JWTAuthenticator {
	a, err := auth.NewJWTAuthenticator(testJWTSecret)
	if err != nil {
		panic(err)
	}
	return a
}()

func testToken(t *testing.T) string {
	t.Helper()
	a, err := auth.NewJWTAuthenticator(testJWTSecret)
	require.NoError(t, err)
	tok, err := a.CreateToken("test-user", "test@example.com")
	require.NoError(t, err)
	return tok
}

func TestCORS_DefaultOrigin(t *testing.T) {
	router := NewRouter(RouterConfig{Usecases: corsMock, CORSOrigins: "", JWTAuth: testJWTAuth})
	req := httptest.NewRequest("OPTIONS", "/api/v1/health", nil)
	req.Header.Set("Origin", "http://localhost:5173")
	req.Header.Set("Access-Control-Request-Method", "GET")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "http://localhost:5173", w.Header().Get("Access-Control-Allow-Origin"))
	assert.NotEmpty(t, w.Header().Get("Access-Control-Allow-Methods"))
}

func TestCORS_CustomOrigins(t *testing.T) {
	router := NewRouter(RouterConfig{Usecases: corsMock, CORSOrigins: "https://app.example.com,https://admin.example.com", JWTAuth: testJWTAuth})
	req := httptest.NewRequest("OPTIONS", "/api/v1/health", nil)
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Access-Control-Request-Method", "GET")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "https://app.example.com", w.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORS_DisallowedOrigin(t *testing.T) {
	router := NewRouter(RouterConfig{Usecases: corsMock, CORSOrigins: "http://localhost:5173", JWTAuth: testJWTAuth})
	req := httptest.NewRequest("OPTIONS", "/api/v1/health", nil)
	req.Header.Set("Origin", "https://evil.com")
	req.Header.Set("Access-Control-Request-Method", "GET")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORS_HeadersOnGET(t *testing.T) {
	router := NewRouter(RouterConfig{Usecases: corsMock, CORSOrigins: "", JWTAuth: testJWTAuth})
	req := httptest.NewRequest("GET", "/api/v1/health", nil)
	req.Header.Set("Origin", "http://localhost:5173")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "http://localhost:5173", w.Header().Get("Access-Control-Allow-Origin"))
}

func TestNewRouterRoutes(t *testing.T) {
	mock := &mockUsecases{
		listProjectsFn: func(ctx context.Context) ([]usecase.ProjectResponse, error) { return nil, nil },
		getProjectFn:   func(ctx context.Context, slug string) (*usecase.ProjectResponse, error) { return nil, nil },
		listFindingsFn: func(ctx context.Context, projectSlug string, severities, states []string, limit, offset int32) ([]usecase.FindingResponse, error) { return nil, nil },
		listReportsFn:  func(ctx context.Context, projectSlug string, limit, offset int32) ([]usecase.ReportResponse, error) { return nil, nil },
		getReportFn:    func(ctx context.Context, id pgtype.UUID) (*usecase.ReportResponse, error) { return nil, nil },
		registerFn:     func(ctx context.Context, email, password string) (*usecase.AuthResponse, error) { return nil, nil },
		loginFn:        func(ctx context.Context, email, password string) (*usecase.AuthResponse, error) { return nil, nil },
		createAPIKeyFn: func(ctx context.Context, projectSlug, name string) (*usecase.APIKeyResponse, error) { return nil, nil },
		listAPIKeysFn:  func(ctx context.Context, projectSlug string) ([]usecase.APIKeyResponse, error) { return nil, nil },
		revokeAPIKeyFn: func(ctx context.Context, projectSlug, keyID string) error { return nil },
	}
	router := NewRouter(RouterConfig{Usecases: mock, JWTAuth: testJWTAuth})
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

	t.Run("unauthenticated request returns 401", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/projects", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("unknown route with auth returns 404", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/nonexistent", nil)
		req.Header.Set("Authorization", "Bearer "+testToken(t))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("auth register endpoint exists", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/auth/register", strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.NotEqual(t, http.StatusNotFound, w.Code)
	})

	t.Run("auth login endpoint exists", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.NotEqual(t, http.StatusNotFound, w.Code)
	})

	t.Run("auth apikeys endpoint exists", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/auth/apikeys", strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.NotEqual(t, http.StatusNotFound, w.Code)
	})
}

func TestRegister_Success(t *testing.T) {
	mock := &mockUsecases{
		registerFn: func(ctx context.Context, email, password string) (*usecase.AuthResponse, error) {
			return &usecase.AuthResponse{Token: "tok", UserID: "u1", Email: email}, nil
		},
	}
	router := testRouter(mock)
	body := strings.NewReader(`{"email":"a@b.com","password":"secret"}`)
	req := httptest.NewRequest("POST", "/api/v1/auth/register", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	var resp usecase.AuthResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "a@b.com", resp.Email)
}

func TestRegister_InvalidBody(t *testing.T) {
	router := testRouter(nil)
	req := httptest.NewRequest("POST", "/api/v1/auth/register", strings.NewReader(`not json`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestLogin_Success(t *testing.T) {
	mock := &mockUsecases{
		loginFn: func(ctx context.Context, email, password string) (*usecase.AuthResponse, error) {
			return &usecase.AuthResponse{Token: "tok", UserID: "u1", Email: email}, nil
		},
	}
	router := testRouter(mock)
	body := strings.NewReader(`{"email":"a@b.com","password":"secret"}`)
	req := httptest.NewRequest("POST", "/api/v1/auth/login", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp usecase.AuthResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "a@b.com", resp.Email)
}

func TestLogin_Failure(t *testing.T) {
	mock := &mockUsecases{
		loginFn: func(ctx context.Context, email, password string) (*usecase.AuthResponse, error) {
			return nil, fmt.Errorf("invalid email or password")
		},
	}
	router := testRouter(mock)
	body := strings.NewReader(`{"email":"a@b.com","password":"wrong"}`)
	req := httptest.NewRequest("POST", "/api/v1/auth/login", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestCreateAPIKey_Success(t *testing.T) {
	mock := &mockUsecases{
		createAPIKeyFn: func(ctx context.Context, projectSlug, name string) (*usecase.APIKeyResponse, error) {
			return &usecase.APIKeyResponse{ID: "k1", Name: name, KeyPrefix: "vuln_abc", RawKey: "vuln_abc...", CreatedAt: "2026-06-30T12:00:00Z"}, nil
		},
	}
	router := testRouter(mock)
	body := strings.NewReader(`{"project":"my-app","name":"ci-key"}`)
	req := httptest.NewRequest("POST", "/api/v1/auth/apikeys", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	var resp usecase.APIKeyResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "vuln_abc...", resp.RawKey)
}

func TestCreateAPIKey_MissingFields(t *testing.T) {
	router := testRouter(nil)
	body := strings.NewReader(`{}`)
	req := httptest.NewRequest("POST", "/api/v1/auth/apikeys", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListAPIKeys_Success(t *testing.T) {
	mock := &mockUsecases{
		listAPIKeysFn: func(ctx context.Context, projectSlug string) ([]usecase.APIKeyResponse, error) {
			return []usecase.APIKeyResponse{{ID: "k1", Name: "ci-key", KeyPrefix: "vuln_abc"}}, nil
		},
	}
	router := testRouter(mock)
	req := httptest.NewRequest("GET", "/api/v1/auth/apikeys?project=my-app", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp []usecase.APIKeyResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Len(t, resp, 1)
}

func TestListAPIKeys_MissingProject(t *testing.T) {
	router := testRouter(nil)
	req := httptest.NewRequest("GET", "/api/v1/auth/apikeys", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRevokeAPIKey_Success(t *testing.T) {
	mock := &mockUsecases{
		revokeAPIKeyFn: func(ctx context.Context, projectSlug, keyID string) error { return nil },
	}
	router := testRouter(mock)
	req := httptest.NewRequest("DELETE", "/api/v1/auth/apikeys/k1?project=my-app", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
}
