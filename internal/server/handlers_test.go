package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xMinhx/specht/internal/auth"
	"github.com/xMinhx/specht/internal/usecase"
)

type mockUsecases struct {
	createProjectFn      func(ctx context.Context, name, slug, description string) (*usecase.ProjectResponse, error)
	listProjectsFn       func(ctx context.Context) ([]usecase.ProjectResponse, error)
	getProjectFn         func(ctx context.Context, slug string) (*usecase.ProjectResponse, error)
	listFindingsFn       func(ctx context.Context, projectSlug string, filter usecase.FindingFilter, limit, offset int32) ([]usecase.FindingResponse, error)
	listReportsFn        func(ctx context.Context, projectSlug string, limit, offset int32) ([]usecase.ReportResponse, error)
	getReportFn          func(ctx context.Context, reportID string) (*usecase.ReportResponse, error)
	ingestReportFn       func(ctx context.Context, input usecase.IngestReportInput) (*usecase.IngestReportOutput, error)
	registerFn           func(ctx context.Context, email, password string) (*usecase.AuthResponse, error)
	loginFn              func(ctx context.Context, email, password string) (*usecase.AuthResponse, error)
	createAPIKeyFn       func(ctx context.Context, projectSlug, name string) (*usecase.APIKeyResponse, error)
	listAPIKeysFn        func(ctx context.Context, projectSlug string) ([]usecase.APIKeyResponse, error)
	revokeAPIKeyFn       func(ctx context.Context, projectSlug, keyID string) error
	triageFindingFn      func(ctx context.Context, input usecase.TriageInput) (*usecase.TriageOutput, error)
	bulkTriageFn         func(ctx context.Context, input usecase.BulkTriageInput) ([]usecase.TriageOutput, error)
	getGateStatusFn      func(ctx context.Context, slug string, minRank int16) (*usecase.GateStatusOutput, error)
	getFindingFn         func(ctx context.Context, findingID string) (*usecase.FindingResponse, error)
	getFindingEventsFn   func(ctx context.Context, findingID string, eventTypes []string, limit, offset int32) ([]usecase.FindingEvent, error)
	refreshFn            func(ctx context.Context, refreshToken string) (*usecase.AuthResponse, error)
	logoutFn             func(ctx context.Context, refreshToken string) error
	getProfileFn         func(ctx context.Context, userID string) (*usecase.UserProfile, error)
	listEnvironmentsFn   func(ctx context.Context, slug string) ([]usecase.EnvironmentResponse, error)
	listTargetsFn        func(ctx context.Context, slug string) ([]usecase.TargetResponse, error)
	listArtifactsFn      func(ctx context.Context, slug string) ([]usecase.ArtifactResponse, error)
	createWaiverFn       func(ctx context.Context, input usecase.CreateWaiverInput) (*usecase.WaiverResponse, error)
	listWaiversFn        func(ctx context.Context, projectSlug string) ([]usecase.WaiverResponse, error)
	getWaiverFn          func(ctx context.Context, projectSlug, waiverID string) (*usecase.WaiverDetailResponse, error)
	updateWaiverFn       func(ctx context.Context, input usecase.UpdateWaiverInput) (*usecase.WaiverResponse, error)
	deleteWaiverFn       func(ctx context.Context, projectSlug, waiverID string) error
	toggleWaiverFn       func(ctx context.Context, projectSlug, waiverID, actorID string) (*usecase.WaiverResponse, error)
	listWaiverEventsFn   func(ctx context.Context, projectSlug, waiverID string) ([]usecase.WaiverEventResp, error)
	checkWaiverMatchFn   func(ctx context.Context, projectSlug, findingID string) (bool, error)
	getProjectStatsFn    func(ctx context.Context, projectSlug string) (*usecase.ProjectStats, error)
	verifyFixFn          func(ctx context.Context, findingID string) (*usecase.VerifyResponse, error)
	getAgingFn           func(ctx context.Context, projectSlug string) (*usecase.AgingResponse, error)
	getWatcherStatusFn   func(ctx context.Context) (*usecase.WatcherStatusResponse, error)
	listScannersFn       func() []usecase.ScannerDescriptorResponse
	createEvidenceFn     func(ctx context.Context, findingID, userID, typ, url, description string) (usecase.EvidenceResponse, error)
	listEvidenceFn       func(ctx context.Context, findingID string) ([]usecase.EvidenceResponse, error)
	deleteEvidenceFn     func(ctx context.Context, evidenceID string) error
	upsertReachabilityFn func(ctx context.Context, findingID, userID, state, evidence string) (*usecase.ReachabilityResponse, error)
	listReachabilityFn   func(ctx context.Context, findingID string) ([]usecase.ReachabilityResponse, error)
	upsertSignoffFn      func(ctx context.Context, findingID, userID, status, comment string) (*usecase.SignoffResponse, error)
	getSignoffFn         func(ctx context.Context, findingID string) (*usecase.SignoffResponse, error)
}

func (m *mockUsecases) CreateProject(ctx context.Context, name, slug, description string) (*usecase.ProjectResponse, error) {
	if m.createProjectFn == nil {
		return nil, fmt.Errorf("unexpected call to CreateProject")
	}
	return m.createProjectFn(ctx, name, slug, description)
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

func (m *mockUsecases) ListFindings(ctx context.Context, projectSlug string, filter usecase.FindingFilter, limit, offset int32) ([]usecase.FindingResponse, error) {
	if m.listFindingsFn == nil {
		return nil, fmt.Errorf("unexpected call to ListFindings")
	}
	return m.listFindingsFn(ctx, projectSlug, filter, limit, offset)
}

func (m *mockUsecases) GetFinding(ctx context.Context, findingID string) (*usecase.FindingResponse, error) {
	if m.getFindingFn == nil {
		return nil, fmt.Errorf("unexpected call to GetFinding")
	}
	return m.getFindingFn(ctx, findingID)
}

func (m *mockUsecases) ListReports(ctx context.Context, projectSlug string, limit, offset int32) ([]usecase.ReportResponse, error) {
	if m.listReportsFn == nil {
		return nil, fmt.Errorf("unexpected call to ListReports")
	}
	return m.listReportsFn(ctx, projectSlug, limit, offset)
}

func (m *mockUsecases) GetReport(ctx context.Context, reportID string) (*usecase.ReportResponse, error) {
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

func (m *mockUsecases) CreateAPIKey(ctx context.Context, projectSlug, name, createdBy string) (*usecase.APIKeyResponse, error) {
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

func (m *mockUsecases) TriageFinding(ctx context.Context, input usecase.TriageInput) (*usecase.TriageOutput, error) {
	if m.triageFindingFn == nil {
		return nil, fmt.Errorf("unexpected call to TriageFinding")
	}
	return m.triageFindingFn(ctx, input)
}

func (m *mockUsecases) VerifyFix(ctx context.Context, findingID string) (*usecase.VerifyResponse, error) {
	if m.verifyFixFn == nil {
		return nil, fmt.Errorf("unexpected call to VerifyFix")
	}
	return m.verifyFixFn(ctx, findingID)
}

func (m *mockUsecases) BulkTriage(ctx context.Context, input usecase.BulkTriageInput) ([]usecase.TriageOutput, error) {
	if m.bulkTriageFn == nil {
		return nil, fmt.Errorf("unexpected call to BulkTriage")
	}
	return m.bulkTriageFn(ctx, input)
}

func (m *mockUsecases) GetGateStatus(ctx context.Context, slug string, minRank int16) (*usecase.GateStatusOutput, error) {
	if m.getGateStatusFn == nil {
		return nil, fmt.Errorf("unexpected call to GetGateStatus")
	}
	return m.getGateStatusFn(ctx, slug, minRank)
}

func (m *mockUsecases) GetFindingEvents(ctx context.Context, findingID string, eventTypes []string, limit, offset int32) ([]usecase.FindingEvent, error) {
	if m.getFindingEventsFn == nil {
		return nil, nil
	}
	return m.getFindingEventsFn(ctx, findingID, eventTypes, limit, offset)
}

func (m *mockUsecases) Refresh(ctx context.Context, refreshToken string) (*usecase.AuthResponse, error) {
	if m.refreshFn == nil {
		return nil, fmt.Errorf("unexpected call to Refresh")
	}
	return m.refreshFn(ctx, refreshToken)
}

func (m *mockUsecases) Logout(ctx context.Context, refreshToken string) error {
	if m.logoutFn == nil {
		return fmt.Errorf("unexpected call to Logout")
	}
	return m.logoutFn(ctx, refreshToken)
}

func (m *mockUsecases) GetProfile(ctx context.Context, userID string) (*usecase.UserProfile, error) {
	if m.getProfileFn == nil {
		return nil, fmt.Errorf("unexpected call to GetProfile")
	}
	return m.getProfileFn(ctx, userID)
}

func (m *mockUsecases) ListEnvironments(ctx context.Context, slug string) ([]usecase.EnvironmentResponse, error) {
	if m.listEnvironmentsFn == nil {
		return nil, fmt.Errorf("unexpected call to ListEnvironments")
	}
	return m.listEnvironmentsFn(ctx, slug)
}

func (m *mockUsecases) ListTargets(ctx context.Context, slug string) ([]usecase.TargetResponse, error) {
	if m.listTargetsFn == nil {
		return nil, fmt.Errorf("unexpected call to ListTargets")
	}
	return m.listTargetsFn(ctx, slug)
}

func (m *mockUsecases) ListArtifacts(ctx context.Context, slug string) ([]usecase.ArtifactResponse, error) {
	if m.listArtifactsFn == nil {
		return nil, fmt.Errorf("unexpected call to ListArtifacts")
	}
	return m.listArtifactsFn(ctx, slug)
}

func (m *mockUsecases) CreateWaiver(ctx context.Context, input usecase.CreateWaiverInput) (*usecase.WaiverResponse, error) {
	if m.createWaiverFn == nil {
		return nil, fmt.Errorf("unexpected call to CreateWaiver")
	}
	return m.createWaiverFn(ctx, input)
}

func (m *mockUsecases) ListWaivers(ctx context.Context, projectSlug string) ([]usecase.WaiverResponse, error) {
	if m.listWaiversFn == nil {
		return nil, fmt.Errorf("unexpected call to ListWaivers")
	}
	return m.listWaiversFn(ctx, projectSlug)
}

func (m *mockUsecases) GetWaiver(ctx context.Context, projectSlug, waiverID string) (*usecase.WaiverDetailResponse, error) {
	if m.getWaiverFn == nil {
		return nil, fmt.Errorf("unexpected call to GetWaiver")
	}
	return m.getWaiverFn(ctx, projectSlug, waiverID)
}

func (m *mockUsecases) UpdateWaiver(ctx context.Context, input usecase.UpdateWaiverInput) (*usecase.WaiverResponse, error) {
	if m.updateWaiverFn == nil {
		return nil, fmt.Errorf("unexpected call to UpdateWaiver")
	}
	return m.updateWaiverFn(ctx, input)
}

func (m *mockUsecases) DeleteWaiver(ctx context.Context, projectSlug, waiverID string) error {
	if m.deleteWaiverFn == nil {
		return fmt.Errorf("unexpected call to DeleteWaiver")
	}
	return m.deleteWaiverFn(ctx, projectSlug, waiverID)
}

func (m *mockUsecases) ToggleWaiver(ctx context.Context, projectSlug, waiverID, actorID string) (*usecase.WaiverResponse, error) {
	if m.toggleWaiverFn == nil {
		return nil, fmt.Errorf("unexpected call to ToggleWaiver")
	}
	return m.toggleWaiverFn(ctx, projectSlug, waiverID, actorID)
}

func (m *mockUsecases) ListWaiverEvents(ctx context.Context, projectSlug, waiverID string) ([]usecase.WaiverEventResp, error) {
	if m.listWaiverEventsFn == nil {
		return nil, fmt.Errorf("unexpected call to ListWaiverEvents")
	}
	return m.listWaiverEventsFn(ctx, projectSlug, waiverID)
}

func (m *mockUsecases) CheckWaiverMatch(ctx context.Context, projectSlug, findingID string) (bool, error) {
	if m.checkWaiverMatchFn == nil {
		return false, fmt.Errorf("unexpected call to CheckWaiverMatch")
	}
	return m.checkWaiverMatchFn(ctx, projectSlug, findingID)
}

func (m *mockUsecases) GetProjectStats(ctx context.Context, projectSlug string) (*usecase.ProjectStats, error) {
	if m.getProjectStatsFn == nil {
		return nil, fmt.Errorf("unexpected call to GetProjectStats")
	}
	return m.getProjectStatsFn(ctx, projectSlug)
}

func (m *mockUsecases) GetAging(ctx context.Context, projectSlug string) (*usecase.AgingResponse, error) {
	if m.getAgingFn == nil {
		return nil, fmt.Errorf("unexpected call to GetAging")
	}
	return m.getAgingFn(ctx, projectSlug)
}

func (m *mockUsecases) GetWatcherStatus(ctx context.Context) (*usecase.WatcherStatusResponse, error) {
	if m.getWatcherStatusFn == nil {
		return nil, fmt.Errorf("unexpected call to GetWatcherStatus")
	}
	return m.getWatcherStatusFn(ctx)
}

func (m *mockUsecases) ListScanners() []usecase.ScannerDescriptorResponse {
	if m.listScannersFn == nil {
		return nil
	}
	return m.listScannersFn()
}

func (m *mockUsecases) CreateEvidence(ctx context.Context, findingID, userID, typ, url, description string) (usecase.EvidenceResponse, error) {
	if m.createEvidenceFn == nil {
		return usecase.EvidenceResponse{}, fmt.Errorf("unexpected call to CreateEvidence")
	}
	return m.createEvidenceFn(ctx, findingID, userID, typ, url, description)
}

func (m *mockUsecases) ListEvidence(ctx context.Context, findingID string) ([]usecase.EvidenceResponse, error) {
	if m.listEvidenceFn == nil {
		return nil, fmt.Errorf("unexpected call to ListEvidence")
	}
	return m.listEvidenceFn(ctx, findingID)
}

func (m *mockUsecases) DeleteEvidence(ctx context.Context, evidenceID string) error {
	if m.deleteEvidenceFn == nil {
		return fmt.Errorf("unexpected call to DeleteEvidence")
	}
	return m.deleteEvidenceFn(ctx, evidenceID)
}

func (m *mockUsecases) UpsertReachability(ctx context.Context, findingID, userID, state, evidence string) (*usecase.ReachabilityResponse, error) {
	if m.upsertReachabilityFn == nil {
		return nil, fmt.Errorf("unexpected call to UpsertReachability")
	}
	return m.upsertReachabilityFn(ctx, findingID, userID, state, evidence)
}

func (m *mockUsecases) ListReachability(ctx context.Context, findingID string) ([]usecase.ReachabilityResponse, error) {
	if m.listReachabilityFn == nil {
		return nil, fmt.Errorf("unexpected call to ListReachability")
	}
	return m.listReachabilityFn(ctx, findingID)
}

func (m *mockUsecases) UpsertSignoff(ctx context.Context, findingID, userID, status, comment string) (*usecase.SignoffResponse, error) {
	if m.upsertSignoffFn == nil {
		return nil, fmt.Errorf("unexpected call to UpsertSignoff")
	}
	return m.upsertSignoffFn(ctx, findingID, userID, status, comment)
}

func (m *mockUsecases) GetSignoff(ctx context.Context, findingID string) (*usecase.SignoffResponse, error) {
	if m.getSignoffFn == nil {
		return nil, fmt.Errorf("unexpected call to GetSignoff")
	}
	return m.getSignoffFn(ctx, findingID)
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
	handler := &Handler{}
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
	handler := &Handler{}

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
	var got usecase.IngestReportInput
	mock := &mockUsecases{
		ingestReportFn: func(ctx context.Context, input usecase.IngestReportInput) (*usecase.IngestReportOutput, error) {
			got = input
			return &usecase.IngestReportOutput{ReportID: "rep-1", TotalFindings: 3, ThresholdBreached: true}, nil
		},
	}
	router := testRouter(mock)
	body := strings.NewReader(`{"project":"my-app","scanner":"trivy","raw_data":{"image":"myapp:latest"},"branch":"main","commit_sha":"abc","environment":"ci","owner":"team-a","digest":"sha256:deadbeef"}`)
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
	assert.Equal(t, "main", got.Branch)
	assert.Equal(t, "abc", got.CommitSha)
	assert.Equal(t, "ci", got.Environment)
	assert.Equal(t, "team-a", got.Owner)
	assert.Equal(t, "sha256:deadbeef", got.Digest)
}

func TestIngestReport_Duplicate(t *testing.T) {
	mock := &mockUsecases{
		ingestReportFn: func(ctx context.Context, input usecase.IngestReportInput) (*usecase.IngestReportOutput, error) {
			return nil, usecase.ErrDuplicateReport
		},
	}
	router := testRouter(mock)
	body := strings.NewReader(`{"project":"my-app","scanner":"trivy","raw_data":{"image":"myapp:latest"}}`)
	req := httptest.NewRequest("POST", "/api/v1/reports", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusConflict, w.Code)
	var resp struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "duplicate_report", resp.Error.Code)
}

func testRouter(mock *mockUsecases) http.Handler {
	r := chi.NewRouter()
	h := NewHandler(mock)
	r.Get("/api/v1/projects", h.ListProjects)
	r.Post("/api/v1/projects", h.CreateProject)
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
	r.Patch("/api/v1/findings/{id}", h.TriageFinding)
	r.Post("/api/v1/findings/{id}/verify", h.VerifyFinding)
	r.Post("/api/v1/findings/bulk-analysis", h.BulkTriage)
	r.Get("/api/v1/findings/{id}/events", h.ListFindingEvents)
	r.Get("/api/v1/findings/{id}", h.GetFinding)
	r.Post("/api/v1/auth/refresh", h.Refresh)
	r.Post("/api/v1/auth/logout", h.Logout)
	r.Get("/api/v1/me", h.Me)
	r.Get("/api/v1/projects/{slug}/gate", h.GetGateStatus)
	r.Get("/api/v1/projects/{slug}/stats", h.GetProjectStats)
	r.Get("/api/v1/projects/{slug}/aging", h.GetAging)
	r.Get("/api/v1/watcher/status", h.GetWatcherStatus)
	r.Get("/api/v1/scanners", h.ListScanners)
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
	h := &Handler{usecase: mock}
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

func TestCreateProject_Success(t *testing.T) {
	mock := &mockUsecases{
		createProjectFn: func(ctx context.Context, name, slug, description string) (*usecase.ProjectResponse, error) {
			return &usecase.ProjectResponse{
				ID:   "proj-1",
				Slug: slug,
				Name: name,
			}, nil
		},
	}
	router := testRouter(mock)
	body := `{"name":"My App","slug":"my-app","description":"test"}`
	req := httptest.NewRequest("POST", "/api/v1/projects", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	var resp usecase.ProjectResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "my-app", resp.Slug)
	assert.Equal(t, "My App", resp.Name)
}

func TestCreateProject_MissingFields(t *testing.T) {
	mock := &mockUsecases{}
	h := &Handler{usecase: mock}
	req := httptest.NewRequest("POST", "/api/v1/projects", strings.NewReader(`{"slug":"my-app"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateProject(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListFindings_Success(t *testing.T) {
	mock := &mockUsecases{
		listFindingsFn: func(ctx context.Context, projectSlug string, filter usecase.FindingFilter, limit, offset int32) ([]usecase.FindingResponse, error) {
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
		listFindingsFn: func(ctx context.Context, projectSlug string, filter usecase.FindingFilter, limit, offset int32) ([]usecase.FindingResponse, error) {
			assert.Equal(t, []string{"high", "critical"}, filter.Severities)
			assert.Equal(t, []string{"open"}, filter.States)
			assert.Equal(t, []string{"production"}, filter.Environments)
			assert.Equal(t, []string{"web"}, filter.Targets)
			assert.Equal(t, int32(50), limit)
			assert.Equal(t, int32(10), offset)
			return sampleFindings(), nil
		},
	}
	router := testRouter(mock)
	req := httptest.NewRequest("GET", "/api/v1/projects/my-app/findings?severity=high,critical&status=open&environment=production&target=web&limit=50&offset=10", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestListFindings_NotFound(t *testing.T) {
	mock := &mockUsecases{
		listFindingsFn: func(ctx context.Context, projectSlug string, filter usecase.FindingFilter, limit, offset int32) ([]usecase.FindingResponse, error) {
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
		getReportFn: func(ctx context.Context, id string) (*usecase.ReportResponse, error) {
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
		getReportFn: func(ctx context.Context, id string) (*usecase.ReportResponse, error) {
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
	tok, err := a.CreateToken("test-user", "test@example.com", auth.RoleViewer)
	require.NoError(t, err)
	return tok
}

func makeTestToken(t *testing.T, role string) string {
	t.Helper()
	a, err := auth.NewJWTAuthenticator(testJWTSecret)
	require.NoError(t, err)
	tok, err := a.CreateToken("test-user", "test@example.com", role)
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
		listFindingsFn: func(ctx context.Context, projectSlug string, filter usecase.FindingFilter, limit, offset int32) ([]usecase.FindingResponse, error) {
			return nil, nil
		},
		listReportsFn: func(ctx context.Context, projectSlug string, limit, offset int32) ([]usecase.ReportResponse, error) {
			return nil, nil
		},
		getReportFn:    func(ctx context.Context, id string) (*usecase.ReportResponse, error) { return nil, nil },
		registerFn:     func(ctx context.Context, email, password string) (*usecase.AuthResponse, error) { return nil, nil },
		loginFn:        func(ctx context.Context, email, password string) (*usecase.AuthResponse, error) { return nil, nil },
		createAPIKeyFn: func(ctx context.Context, projectSlug, name string) (*usecase.APIKeyResponse, error) { return nil, nil },
		listAPIKeysFn:  func(ctx context.Context, projectSlug string) ([]usecase.APIKeyResponse, error) { return nil, nil },
		revokeAPIKeyFn: func(ctx context.Context, projectSlug, keyID string) error { return nil },
		getFindingFn:   func(ctx context.Context, findingID string) (*usecase.FindingResponse, error) { return nil, nil },
		checkWaiverMatchFn: func(ctx context.Context, projectSlug, findingID string) (bool, error) {
			return true, nil
		},
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

	t.Run("waiver check match accepts POST", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/projects/my-app/waivers/check-match", strings.NewReader(`{"finding_id":"f1"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+testToken(t))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
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
	req = req.WithContext(auth.ContextWithIdentity(req.Context(), &auth.Identity{UserID: "test-user"}))
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

func authRequest(method, path, body string) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	ctx := auth.ContextWithIdentity(r.Context(), &auth.Identity{UserID: "test-user"})
	return r.WithContext(ctx)
}

func TestTriageFinding_Success(t *testing.T) {
	mock := &mockUsecases{
		triageFindingFn: func(ctx context.Context, input usecase.TriageInput) (*usecase.TriageOutput, error) {
			return &usecase.TriageOutput{FindingID: "abc-123", AnalysisState: "false_positive", GateEffect: "ignore"}, nil
		},
	}
	router := testRouter(mock)
	req := authRequest("PATCH", "/api/v1/findings/abc-123", `{"analysis_state":"false_positive","reason":"test code only"}`)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp usecase.TriageOutput
	json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Equal(t, "false_positive", resp.AnalysisState)
}

func TestVerifyFinding_Success(t *testing.T) {
	mock := &mockUsecases{
		verifyFixFn: func(ctx context.Context, findingID string) (*usecase.VerifyResponse, error) {
			assert.Equal(t, "abc-123", findingID)
			return &usecase.VerifyResponse{FindingID: "abc-123", Outcome: usecase.VerifyFixed, Detail: "absent from rescan"}, nil
		},
	}
	router := testRouter(mock)
	req := authRequest("POST", "/api/v1/findings/abc-123/verify", "{}")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp usecase.VerifyResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Equal(t, usecase.VerifyFixed, resp.Outcome)
}

func TestTriageFinding_MissingReason(t *testing.T) {
	mock := &mockUsecases{
		triageFindingFn: func(ctx context.Context, input usecase.TriageInput) (*usecase.TriageOutput, error) {
			return nil, usecase.ErrReasonRequired
		},
	}
	router := testRouter(mock)
	req := authRequest("PATCH", "/api/v1/findings/abc-123", `{"analysis_state":"false_positive"}`)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
}

func TestTriageFinding_MissingExpiry(t *testing.T) {
	mock := &mockUsecases{
		triageFindingFn: func(ctx context.Context, input usecase.TriageInput) (*usecase.TriageOutput, error) {
			return nil, usecase.ErrExpiryRequired
		},
	}
	router := testRouter(mock)
	req := authRequest("PATCH", "/api/v1/findings/abc-123", `{"analysis_state":"accepted_risk","reason":"ok for now"}`)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
}

func TestTriageFinding_InvalidState(t *testing.T) {
	mock := &mockUsecases{
		triageFindingFn: func(ctx context.Context, input usecase.TriageInput) (*usecase.TriageOutput, error) {
			return nil, usecase.ErrInvalidState
		},
	}
	router := testRouter(mock)
	req := authRequest("PATCH", "/api/v1/findings/abc-123", `{"analysis_state":"bogus"}`)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
}

func TestBulkTriage_InvalidState(t *testing.T) {
	mock := &mockUsecases{
		bulkTriageFn: func(ctx context.Context, input usecase.BulkTriageInput) ([]usecase.TriageOutput, error) {
			return nil, usecase.ErrInvalidState
		},
	}
	router := testRouter(mock)
	req := authRequest("POST", "/api/v1/findings/bulk-analysis", `{"finding_ids":["abc-123"],"analysis_state":"bogus"}`)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
}

func TestBulkTriage_Success(t *testing.T) {
	mock := &mockUsecases{
		bulkTriageFn: func(ctx context.Context, input usecase.BulkTriageInput) ([]usecase.TriageOutput, error) {
			return []usecase.TriageOutput{
				{FindingID: "abc-123", AnalysisState: "false_positive", GateEffect: "ignore"},
				{FindingID: "def-456", AnalysisState: "false_positive", GateEffect: "ignore"},
			}, nil
		},
	}
	router := testRouter(mock)
	req := authRequest("POST", "/api/v1/findings/bulk-analysis", `{"finding_ids":["abc-123","def-456"],"analysis_state":"false_positive","reason":"test code"}`)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGateStatus_Success(t *testing.T) {
	mock := &mockUsecases{
		getGateStatusFn: func(ctx context.Context, slug string, minRank int16) (*usecase.GateStatusOutput, error) {
			return &usecase.GateStatusOutput{ThresholdBreached: false, BlockingCount: 0}, nil
		},
	}
	router := testRouter(mock)
	req := httptest.NewRequest("GET", "/api/v1/projects/my-app/gate", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp usecase.GateStatusOutput
	json.Unmarshal(w.Body.Bytes(), &resp)
	assert.False(t, resp.ThresholdBreached)
}

func TestGateStatus_Breached(t *testing.T) {
	mock := &mockUsecases{
		getGateStatusFn: func(ctx context.Context, slug string, minRank int16) (*usecase.GateStatusOutput, error) {
			return &usecase.GateStatusOutput{ThresholdBreached: true, BlockingCount: 3}, nil
		},
	}
	router := testRouter(mock)
	req := httptest.NewRequest("GET", "/api/v1/projects/my-app/gate", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestStats_Success(t *testing.T) {
	mock := &mockUsecases{
		getProjectStatsFn: func(ctx context.Context, slug string) (*usecase.ProjectStats, error) {
			return &usecase.ProjectStats{
				TotalFindings: 42,
				BlockingCount: 3,
				WaiverCount:   5,
				ReportCount:   10,
				BySeverity: []usecase.SeverityCount{
					{Severity: "critical", Count: 2, BlockingCount: 2},
					{Severity: "high", Count: 10, BlockingCount: 1},
				},
			}, nil
		},
	}
	router := testRouter(mock)
	req := httptest.NewRequest("GET", "/api/v1/projects/my-app/stats", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp usecase.ProjectStats
	json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Equal(t, int32(42), resp.TotalFindings)
	assert.Equal(t, int32(3), resp.BlockingCount)
	assert.Equal(t, int32(5), resp.WaiverCount)
	assert.Equal(t, int32(10), resp.ReportCount)
	assert.Len(t, resp.BySeverity, 2)
}

func TestStats_ProjectNotFound(t *testing.T) {
	mock := &mockUsecases{
		getProjectStatsFn: func(ctx context.Context, slug string) (*usecase.ProjectStats, error) {
			return nil, fmt.Errorf("project not found")
		},
	}
	router := testRouter(mock)
	req := httptest.NewRequest("GET", "/api/v1/projects/unknown/stats", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestAging_Success(t *testing.T) {
	mock := &mockUsecases{
		getAgingFn: func(ctx context.Context, slug string) (*usecase.AgingResponse, error) {
			assert.Equal(t, "my-app", slug)
			return &usecase.AgingResponse{
				Buckets:      []usecase.AgingBucketCount{{Bucket: "debt", Count: 2, Overdue: 1}},
				OverdueTotal: 1,
				Reopened:     1,
			}, nil
		},
	}
	router := testRouter(mock)
	req := httptest.NewRequest("GET", "/api/v1/projects/my-app/aging", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp usecase.AgingResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, int32(1), resp.OverdueTotal)
	assert.Equal(t, int32(1), resp.Reopened)
}

func TestListFindingEvents_Success(t *testing.T) {
	mock := &mockUsecases{
		getFindingEventsFn: func(ctx context.Context, findingID string, eventTypes []string, limit, offset int32) ([]usecase.FindingEvent, error) {
			return []usecase.FindingEvent{{EventType: "analysis_changed"}}, nil
		},
	}
	router := testRouter(mock)
	req := httptest.NewRequest("GET", "/api/v1/findings/abc-123/events", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// ----- GetFinding Handler Tests -----

func TestGetFinding_Success(t *testing.T) {
	mock := &mockUsecases{
		getFindingFn: func(ctx context.Context, findingID string) (*usecase.FindingResponse, error) {
			return &usecase.FindingResponse{ID: findingID, FindingKind: "sca", CurrentTitle: "CVE-2026-0001"}, nil
		},
	}
	router := testRouter(mock)
	req := httptest.NewRequest("GET", "/api/v1/findings/550e8400-e29b-41d4-a716-446655440000", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp usecase.FindingResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "sca", resp.FindingKind)
}

func TestGetFinding_InvalidID(t *testing.T) {
	mock := &mockUsecases{
		getFindingFn: func(ctx context.Context, findingID string) (*usecase.FindingResponse, error) {
			return nil, fmt.Errorf("invalid finding id")
		},
	}
	router := testRouter(mock)
	req := httptest.NewRequest("GET", "/api/v1/findings/not-a-uuid", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetFinding_NotFound(t *testing.T) {
	mock := &mockUsecases{
		getFindingFn: func(ctx context.Context, findingID string) (*usecase.FindingResponse, error) {
			return nil, fmt.Errorf("get finding: not found")
		},
	}
	router := testRouter(mock)
	req := httptest.NewRequest("GET", "/api/v1/findings/550e8400-e29b-41d4-a716-446655440000", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestGetFinding_APIKeyAccessDenied(t *testing.T) {
	mock := &mockUsecases{
		getFindingFn: func(ctx context.Context, findingID string) (*usecase.FindingResponse, error) {
			return nil, usecase.ErrProjectAccessDenied
		},
	}
	h := &Handler{usecase: mock}
	req := httptest.NewRequest("GET", "/api/v1/findings/00000000-0000-0000-0000-000000000021", nil)
	req = req.WithContext(auth.ContextWithIdentity(req.Context(), &auth.Identity{
		UserID: "00000000-0000-0000-0000-000000000040", IsAPIKey: true,
	}))
	req = addChiURLParam(req, "id", "00000000-0000-0000-0000-000000000021")
	w := httptest.NewRecorder()
	h.GetFinding(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

// ----- Refresh Handler Tests -----

func TestRefresh_Success(t *testing.T) {
	mock := &mockUsecases{
		refreshFn: func(ctx context.Context, refreshToken string) (*usecase.AuthResponse, error) {
			return &usecase.AuthResponse{Token: "new-token", RefreshToken: "new-refresh", UserID: "u1", Email: "test@example.com"}, nil
		},
	}
	router := testRouter(mock)
	body := strings.NewReader(`{"refresh_token":"valid-token"}`)
	req := httptest.NewRequest("POST", "/api/v1/auth/refresh", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp usecase.AuthResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Token)
}

func TestRefresh_InvalidBody(t *testing.T) {
	router := testRouter(nil)
	req := httptest.NewRequest("POST", "/api/v1/auth/refresh", strings.NewReader(`not json`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRefresh_Error(t *testing.T) {
	mock := &mockUsecases{
		refreshFn: func(ctx context.Context, refreshToken string) (*usecase.AuthResponse, error) {
			return nil, fmt.Errorf("invalid refresh token")
		},
	}
	router := testRouter(mock)
	body := strings.NewReader(`{"refresh_token":"bad-token"}`)
	req := httptest.NewRequest("POST", "/api/v1/auth/refresh", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ----- Logout Handler Tests -----

func TestLogout_Success(t *testing.T) {
	mock := &mockUsecases{
		logoutFn: func(ctx context.Context, refreshToken string) error { return nil },
	}
	router := testRouter(mock)
	body := strings.NewReader(`{"refresh_token":"valid-token"}`)
	req := httptest.NewRequest("POST", "/api/v1/auth/logout", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
}

func TestLogout_WithError(t *testing.T) {
	mock := &mockUsecases{
		logoutFn: func(ctx context.Context, refreshToken string) error {
			return fmt.Errorf("db error")
		},
	}
	router := testRouter(mock)
	body := strings.NewReader(`{"refresh_token":"some-token"}`)
	req := httptest.NewRequest("POST", "/api/v1/auth/logout", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ----- Me Handler Tests -----

func TestMe_Success(t *testing.T) {
	mock := &mockUsecases{
		getProfileFn: func(ctx context.Context, userID string) (*usecase.UserProfile, error) {
			return &usecase.UserProfile{ID: userID, Email: "test@example.com", Role: "user"}, nil
		},
	}
	router := testRouter(mock)
	req := httptest.NewRequest("GET", "/api/v1/me", nil)
	req = req.WithContext(auth.ContextWithIdentity(req.Context(), &auth.Identity{UserID: "test-user"}))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp usecase.UserProfile
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "test@example.com", resp.Email)
}

func TestMe_NoIdentity(t *testing.T) {
	router := testRouter(nil)
	req := httptest.NewRequest("GET", "/api/v1/me", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestMe_UserNotFound(t *testing.T) {
	mock := &mockUsecases{
		getProfileFn: func(ctx context.Context, userID string) (*usecase.UserProfile, error) {
			return nil, fmt.Errorf("user not found")
		},
	}
	router := testRouter(mock)
	req := httptest.NewRequest("GET", "/api/v1/me", nil)
	req = req.WithContext(auth.ContextWithIdentity(req.Context(), &auth.Identity{UserID: "nonexistent"}))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ----- AuthMiddleware Tests -----

func TestAuthMiddleware_NoHeader(t *testing.T) {
	mw := AuthMiddleware(testJWTAuth)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest("GET", "/api/v1/projects", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthMiddleware_InvalidToken(t *testing.T) {
	mw := AuthMiddleware(testJWTAuth)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest("GET", "/api/v1/projects", nil)
	req.Header.Set("Authorization", "Bearer invalid-jwt-token")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthMiddleware_ExpiredJWTDoesNotFallThrough(t *testing.T) {
	mw := AuthMiddleware(testJWTAuth, auth.NewAPIKeyAuthenticator(func(ctx context.Context, keyHash string) (string, string, error) {
		return "user-1", "project-1", nil
	}))

	// generate an expired JWT that is well-formed but past expiry
	a, err := auth.NewJWTAuthenticator(testJWTSecret)
	require.NoError(t, err)
	expiredTok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":   "test-user",
		"email": "test@example.com",
		"iat":   time.Now().Add(-2 * time.Hour).Unix(),
		"exp":   time.Now().Add(-1 * time.Hour).Unix(),
	}).SignedString([]byte(testJWTSecret))

	require.NoError(t, err)
	_ = a // silence unused

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest("GET", "/api/v1/projects", nil)
	req.Header.Set("Authorization", "Bearer "+expiredTok)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthMiddleware_MalformedTokenFallsThrough(t *testing.T) {
	mw := AuthMiddleware(testJWTAuth, auth.NewAPIKeyAuthenticator(func(ctx context.Context, keyHash string) (string, string, error) {
		return "user-1", "project-1", nil
	}))
	var capturedID string
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ident := auth.ContextIdentity(r.Context())
		capturedID = ident.UserID
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest("GET", "/api/v1/projects", nil)
	req.Header.Set("Authorization", "Bearer not-a-jwt")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "user-1", capturedID)
}

func TestAuthMiddleware_NoAuthenticators(t *testing.T) {
	mw := AuthMiddleware()
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest("GET", "/api/v1/projects", nil)
	req.Header.Set("Authorization", "Bearer some-token")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthMiddleware_APIKeyAuth(t *testing.T) {
	apiKeyAuth := auth.NewAPIKeyAuthenticator(func(ctx context.Context, keyHash string) (string, string, error) {
		return "user-1", "project-1", nil
	})
	mw := AuthMiddleware(testJWTAuth, apiKeyAuth)
	var capturedID string
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ident := auth.ContextIdentity(r.Context())
		capturedID = ident.UserID
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest("GET", "/api/v1/projects", nil)
	req.Header.Set("Authorization", "Bearer some-api-key")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "user-1", capturedID)
}

func TestAPIKeyAuthenticator_IdentitySemantics(t *testing.T) {
	var capturedHash string
	apiKeyAuth := auth.NewAPIKeyAuthenticator(func(ctx context.Context, keyHash string) (string, string, error) {
		capturedHash = keyHash
		return "key-1", "project-1", nil
	})

	ident, err := apiKeyAuth.Authenticate(context.Background(), "vuln_abc123keymaterial")
	require.NoError(t, err)
	assert.Equal(t, "key-1", ident.UserID)
	assert.Equal(t, "", ident.Email)
	assert.Equal(t, "project-1", ident.ProjectID)
	assert.True(t, ident.IsAPIKey)

	h := sha256.Sum256([]byte("vuln_abc123keymaterial"))
	assert.Equal(t, hex.EncodeToString(h[:]), capturedHash)
}

// ----- NewRouter endpoint connectivity -----

func TestNewRouter_RefreshLogoutOutsideAuth(t *testing.T) {
	mock := &mockUsecases{
		refreshFn: func(ctx context.Context, refreshToken string) (*usecase.AuthResponse, error) {
			return &usecase.AuthResponse{Token: "new-tok", RefreshToken: "new-ref", UserID: "u1", Email: "a@b.com"}, nil
		},
		logoutFn: func(ctx context.Context, refreshToken string) error { return nil },
	}
	router := NewRouter(RouterConfig{Usecases: mock, JWTAuth: testJWTAuth})

	t.Run("refresh without auth header succeeds", func(t *testing.T) {
		body := strings.NewReader(`{"refresh_token":"x"}`)
		req := httptest.NewRequest("POST", "/api/v1/auth/refresh", body)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("logout without auth header succeeds", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/auth/logout", strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusNoContent, w.Code)
	})

	t.Run("me without token returns 401", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/me", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

func TestNewRouter_MeWithValidToken(t *testing.T) {
	mock := &mockUsecases{
		getProfileFn: func(ctx context.Context, userID string) (*usecase.UserProfile, error) {
			return &usecase.UserProfile{ID: userID, Email: "test@example.com", Role: "user"}, nil
		},
	}
	router := NewRouter(RouterConfig{Usecases: mock, JWTAuth: testJWTAuth})

	req := httptest.NewRequest("GET", "/api/v1/me", nil)
	req.Header.Set("Authorization", "Bearer "+testToken(t))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// ----- parseMinSeverityRank Tests -----

func TestParseMinSeverityRank(t *testing.T) {
	tests := []struct {
		input string
		want  int16
	}{
		{"", 3},
		{"high", 3},
		{"critical", 4},
		{"medium", 2},
		{"low", 1},
		{"high,critical", 4},
		{"low,medium", 2},
		{"unknown", 3},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := parseMinSeverityRank(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

// ----- parseIntParam Tests -----

func TestParseIntParam(t *testing.T) {
	tests := []struct {
		name       string
		query      string
		defaultVal int32
		want       int32
	}{
		{"no param", "/test", 20, 20},
		{"valid param", "/test?limit=50", 20, 50},
		{"negative param", "/test?limit=-1", 20, 20},
		{"non-numeric", "/test?limit=abc", 20, 20},
		{"zero", "/test?limit=0", 20, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", tt.query, nil)
			got := parseIntParam(r, "limit", tt.defaultVal)
			assert.Equal(t, tt.want, got)
		})
	}
}

func sampleWaiverResponse() usecase.WaiverResponse {
	return usecase.WaiverResponse{
		ID:          "wvr-1",
		ProjectID:   "proj-1",
		Name:        "test-waiver",
		Description: "test description",
		Enabled:     true,
		Conditions:  []usecase.WaiverConditionResp{},
		Contexts:    []usecase.WaiverContextResp{},
		Targets:     []usecase.WaiverFindingTargetResp{},
		CreatedAt:   now.Format(time.RFC3339),
		UpdatedAt:   now.Format(time.RFC3339),
	}
}

func authRouter(h *Handler) http.Handler {
	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := auth.ContextWithIdentity(r.Context(), &auth.Identity{UserID: "test-user"})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})
	r.Route("/api/v1/projects/{slug}/waivers", func(r chi.Router) {
		r.Get("/", h.ListWaivers)
		r.Post("/", h.CreateWaiver)
		r.Get("/{id}", h.GetWaiver)
		r.Put("/{id}", h.UpdateWaiver)
		r.Delete("/{id}", h.DeleteWaiver)
		r.Post("/{id}/toggle", h.ToggleWaiver)
		r.Get("/{id}/events", h.ListWaiverEvents)
		r.Post("/check-match", h.CheckWaiverMatch)
	})
	return r
}

func TestCreateWaiver_Success(t *testing.T) {
	mock := &mockUsecases{
		createWaiverFn: func(ctx context.Context, input usecase.CreateWaiverInput) (*usecase.WaiverResponse, error) {
			assert.Equal(t, "my-app", input.ProjectSlug)
			assert.Equal(t, "test-waiver", input.Name)
			assert.Equal(t, "test-user", input.ActorID)
			r := sampleWaiverResponse()
			return &r, nil
		},
	}
	h := NewHandler(mock)
	router := authRouter(h)
	body := strings.NewReader(`{"name":"test-waiver","description":"test description"}`)
	req := httptest.NewRequest("POST", "/api/v1/projects/my-app/waivers", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	var resp usecase.WaiverResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "test-waiver", resp.Name)
}

func TestCreateWaiver_MissingName(t *testing.T) {
	handler := &Handler{}
	body := strings.NewReader(`{"name":""}`)
	req := httptest.NewRequest("POST", "/api/v1/projects/my-app/waivers", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.CreateWaiver(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListWaivers_Success(t *testing.T) {
	mock := &mockUsecases{
		listWaiversFn: func(ctx context.Context, projectSlug string) ([]usecase.WaiverResponse, error) {
			assert.Equal(t, "my-app", projectSlug)
			return []usecase.WaiverResponse{sampleWaiverResponse()}, nil
		},
	}
	h := NewHandler(mock)
	router := authRouter(h)
	req := httptest.NewRequest("GET", "/api/v1/projects/my-app/waivers", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp []usecase.WaiverResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Len(t, resp, 1)
}

func TestGetWaiver_Success(t *testing.T) {
	mock := &mockUsecases{
		getWaiverFn: func(ctx context.Context, projectSlug, waiverID string) (*usecase.WaiverDetailResponse, error) {
			assert.Equal(t, "my-app", projectSlug)
			assert.Equal(t, "wvr-1", waiverID)
			return &usecase.WaiverDetailResponse{WaiverResponse: sampleWaiverResponse()}, nil
		},
	}
	h := NewHandler(mock)
	router := authRouter(h)
	req := httptest.NewRequest("GET", "/api/v1/projects/my-app/waivers/wvr-1", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestDeleteWaiver_Success(t *testing.T) {
	mock := &mockUsecases{
		deleteWaiverFn: func(ctx context.Context, projectSlug, waiverID string) error {
			assert.Equal(t, "my-app", projectSlug)
			assert.Equal(t, "wvr-1", waiverID)
			return nil
		},
	}
	h := NewHandler(mock)
	router := authRouter(h)
	req := httptest.NewRequest("DELETE", "/api/v1/projects/my-app/waivers/wvr-1", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
}

func TestToggleWaiver_Success(t *testing.T) {
	mock := &mockUsecases{
		toggleWaiverFn: func(ctx context.Context, projectSlug, waiverID, actorID string) (*usecase.WaiverResponse, error) {
			assert.Equal(t, "my-app", projectSlug)
			assert.Equal(t, "wvr-1", waiverID)
			assert.Equal(t, "test-user", actorID)
			r := sampleWaiverResponse()
			r.Enabled = false
			return &r, nil
		},
	}
	h := NewHandler(mock)
	router := authRouter(h)
	req := httptest.NewRequest("POST", "/api/v1/projects/my-app/waivers/wvr-1/toggle", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp usecase.WaiverResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.False(t, resp.Enabled)
}

func TestCheckWaiverMatch_Success(t *testing.T) {
	mock := &mockUsecases{
		checkWaiverMatchFn: func(ctx context.Context, projectSlug, findingID string) (bool, error) {
			assert.Equal(t, "my-app", projectSlug)
			assert.Equal(t, "find-1", findingID)
			return true, nil
		},
	}
	h := NewHandler(mock)
	router := authRouter(h)
	body := strings.NewReader(`{"finding_id":"find-1"}`)
	req := httptest.NewRequest("POST", "/api/v1/projects/my-app/waivers/check-match", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]bool
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.True(t, resp["matched"])
}

func addChiURLParam(r *http.Request, key, value string) *http.Request {
	chiCtx := chi.NewRouteContext()
	chiCtx.URLParams.Add(key, value)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, chiCtx))
}

func TestCheckWaiverMatch_MissingFindingID(t *testing.T) {
	handler := &Handler{}
	body := strings.NewReader(`{}`)
	req := httptest.NewRequest("POST", "/api/v1/projects/my-app/waivers/check-match", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.CheckWaiverMatch(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ----- enforceProjectAccess Tests -----

func TestEnforceProjectAccess_SessionAuthNoScope(t *testing.T) {
	h := &Handler{}
	req := httptest.NewRequest("GET", "/api/v1/projects/my-app", nil)
	req = req.WithContext(auth.ContextWithIdentity(req.Context(), &auth.Identity{UserID: "user-1", IsAPIKey: false}))
	err := h.enforceProjectAccess(req, "my-app")
	assert.NoError(t, err)

	reqNil := httptest.NewRequest("GET", "/api/v1/projects/my-app", nil)
	reqNil = reqNil.WithContext(auth.ContextWithIdentity(reqNil.Context(), &auth.Identity{UserID: "user-1", ProjectID: "", IsAPIKey: false}))
	err = h.enforceProjectAccess(reqNil, "other-project")
	assert.NoError(t, err)
}

func TestEnforceProjectAccess_APIKeyMatching(t *testing.T) {
	projectID := "00000000-0000-0000-0000-000000000001"
	h := &Handler{usecase: &mockUsecases{
		getProjectFn: func(ctx context.Context, slug string) (*usecase.ProjectResponse, error) {
			assert.Equal(t, "my-app", slug)
			return &usecase.ProjectResponse{ID: projectID, Slug: slug}, nil
		},
	}}
	req := httptest.NewRequest("GET", "/api/v1/projects/my-app", nil)
	req = req.WithContext(auth.ContextWithIdentity(req.Context(), &auth.Identity{UserID: "key-1", ProjectID: projectID, IsAPIKey: true}))
	err := h.enforceProjectAccess(req, "my-app")
	assert.NoError(t, err)
}

func TestEnforceProjectAccess_APIKeyNonMatching(t *testing.T) {
	projectID := "00000000-0000-0000-0000-000000000001"
	otherProjectID := "00000000-0000-0000-0000-000000000002"
	h := &Handler{usecase: &mockUsecases{
		getProjectFn: func(ctx context.Context, slug string) (*usecase.ProjectResponse, error) {
			assert.Equal(t, "other-project", slug)
			return &usecase.ProjectResponse{ID: otherProjectID, Slug: slug}, nil
		},
	}}
	req := httptest.NewRequest("GET", "/api/v1/projects/other-project", nil)
	req = req.WithContext(auth.ContextWithIdentity(req.Context(), &auth.Identity{UserID: "key-1", ProjectID: projectID, IsAPIKey: true}))
	err := h.enforceProjectAccess(req, "other-project")
	assert.Error(t, err)
}

func TestEnforceProjectAccess_NilIdentity(t *testing.T) {
	h := &Handler{}
	req := httptest.NewRequest("GET", "/api/v1/projects/my-app", nil)
	err := h.enforceProjectAccess(req, "my-app")
	assert.NoError(t, err)
}

// ----- Handler-level enforcement test -----

func TestListFindings_APIKeyAccessDenied(t *testing.T) {
	projectID := "00000000-0000-0000-0000-000000000001"
	otherProjectID := "00000000-0000-0000-0000-000000000002"
	mock := &mockUsecases{
		getProjectFn: func(ctx context.Context, slug string) (*usecase.ProjectResponse, error) {
			return &usecase.ProjectResponse{ID: otherProjectID, Slug: slug}, nil
		},
	}
	handler := &Handler{usecase: mock}
	req := httptest.NewRequest("GET", "/api/v1/projects/my-app/findings", nil)
	req = req.WithContext(auth.ContextWithIdentity(req.Context(), &auth.Identity{
		UserID: "key-1", ProjectID: projectID, IsAPIKey: true,
	}))
	req = addChiURLParam(req, "slug", "my-app")
	w := httptest.NewRecorder()
	handler.ListFindings(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	var resp struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "project_access_denied", resp.Error.Code)
}

func TestListFindings_APIKeyAllowed(t *testing.T) {
	projectID := "00000000-0000-0000-0000-000000000001"
	mock := &mockUsecases{
		getProjectFn: func(ctx context.Context, slug string) (*usecase.ProjectResponse, error) {
			return &usecase.ProjectResponse{ID: projectID, Slug: slug}, nil
		},
		listFindingsFn: func(ctx context.Context, projectSlug string, filter usecase.FindingFilter, limit, offset int32) ([]usecase.FindingResponse, error) {
			return sampleFindings(), nil
		},
	}
	handler := &Handler{usecase: mock}
	req := httptest.NewRequest("GET", "/api/v1/projects/my-app/findings", nil)
	req = req.WithContext(auth.ContextWithIdentity(req.Context(), &auth.Identity{
		UserID: "key-1", ProjectID: projectID, IsAPIKey: true,
	}))
	req = addChiURLParam(req, "slug", "my-app")
	w := httptest.NewRecorder()
	handler.ListFindings(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestWatcherStatusHandler(t *testing.T) {
	mock := &mockUsecases{
		getWatcherStatusFn: func(ctx context.Context) (*usecase.WatcherStatusResponse, error) {
			return &usecase.WatcherStatusResponse{
				LastSuccessfulPollAt: "2026-09-03T10:00:00Z",
				ConsecutiveFailures:  0,
				Healthy:              true,
			}, nil
		},
	}
	router := testRouter(mock)
	req := httptest.NewRequest("GET", "/api/v1/watcher/status", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp usecase.WatcherStatusResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.True(t, resp.Healthy)
	assert.Equal(t, "2026-09-03T10:00:00Z", resp.LastSuccessfulPollAt)
}

func TestGetGateStatus_APIKeyUUIDProject(t *testing.T) {
	projectID := "00000000-0000-0000-0000-000000000001"
	mock := &mockUsecases{
		getProjectFn: func(ctx context.Context, slug string) (*usecase.ProjectResponse, error) {
			return &usecase.ProjectResponse{ID: projectID, Slug: slug}, nil
		},
		getGateStatusFn: func(ctx context.Context, slug string, minRank int16) (*usecase.GateStatusOutput, error) {
			assert.Equal(t, "my-app", slug)
			return &usecase.GateStatusOutput{}, nil
		},
	}
	req := httptest.NewRequest("GET", "/api/v1/projects/my-app/gate", nil)
	req = req.WithContext(auth.ContextWithIdentity(req.Context(), &auth.Identity{
		UserID: "key-1", ProjectID: projectID, IsAPIKey: true,
	}))
	w := httptest.NewRecorder()
	testRouter(mock).ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestReachabilityHandlers_InvalidFindingID(t *testing.T) {
	tests := []struct {
		name   string
		method string
		body   string
		handle func(*Handler, http.ResponseWriter, *http.Request)
	}{
		{
			name:   "list",
			method: "GET",
			handle: (*Handler).ListReachability,
		},
		{
			name:   "upsert",
			method: "POST",
			body:   `{"state":"unknown"}`,
			handle: (*Handler).UpsertReachability,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockUsecases{}
			if tt.name == "list" {
				mock.listReachabilityFn = func(ctx context.Context, findingID string) ([]usecase.ReachabilityResponse, error) {
					return nil, usecase.ErrInvalidFindingID
				}
			} else {
				mock.upsertReachabilityFn = func(ctx context.Context, findingID, userID, state, evidence string) (*usecase.ReachabilityResponse, error) {
					return nil, usecase.ErrInvalidFindingID
				}
			}
			h := &Handler{usecase: mock}
			req := httptest.NewRequest(tt.method, "/api/v1/findings/not-a-uuid/reachability", strings.NewReader(tt.body))
			req = addChiURLParam(req, "findingID", "not-a-uuid")
			if tt.name == "upsert" {
				req = req.WithContext(auth.ContextWithIdentity(req.Context(), &auth.Identity{UserID: "user-1"}))
			}
			w := httptest.NewRecorder()
			tt.handle(h, w, req)

			assert.Equal(t, http.StatusBadRequest, w.Code)
			var resp apiError
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
			assert.Equal(t, "invalid_id", resp.Error.Code)
		})
	}
}

func TestListScannersHandler(t *testing.T) {
	mock := &mockUsecases{
		listScannersFn: func() []usecase.ScannerDescriptorResponse {
			return []usecase.ScannerDescriptorResponse{
				{Name: "trivy", Version: "2", FindingKinds: []string{"sca", "secret", "iac"}, ProvidesPackages: true},
				{Name: "semgrep", Version: "2.1", FindingKinds: []string{"sast"}},
			}
		},
	}
	router := testRouter(mock)
	req := httptest.NewRequest("GET", "/api/v1/scanners", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp []usecase.ScannerDescriptorResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	require.Len(t, resp, 2)
	assert.Equal(t, "trivy", resp[0].Name)
	assert.Equal(t, []string{"sca", "secret", "iac"}, resp[0].FindingKinds)
	assert.Equal(t, "semgrep", resp[1].Name)
}

func TestRequireRole_AdminAllowed(t *testing.T) {
	tok := makeTestToken(t, auth.RoleAdmin)
	mw := AuthMiddleware(testJWTAuth)
	roleMw := RequireRole(auth.RoleAdmin)
	handler := mw(roleMw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	req := httptest.NewRequest("POST", "/api/v1/projects", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRequireRole_ViewerDenied(t *testing.T) {
	tok := makeTestToken(t, auth.RoleViewer)
	mw := AuthMiddleware(testJWTAuth)
	roleMw := RequireRole(auth.RoleAdmin)
	handler := mw(roleMw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	req := httptest.NewRequest("POST", "/api/v1/projects", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestRequireRole_UnauthenticatedDenied(t *testing.T) {
	roleMw := RequireRole(auth.RoleAdmin)
	handler := roleMw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest("POST", "/api/v1/projects", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRequireRole_APIKeyBypass(t *testing.T) {
	// API keys are project-scoped and bypass role checks.
	roleMw := RequireRole(auth.RoleAdmin)
	h := roleMw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest("POST", "/api/v1/projects", nil)
	ctx := auth.ContextWithIdentity(context.Background(), &auth.Identity{
		UserID: "key-user", ProjectID: "proj-1", IsAPIKey: true,
	})
	// Simulate the identity being set by AuthMiddleware.
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}
