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

	"github.com/minh-tg/specht/internal/usecase"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// dbErrText mimics a wrapped pgx/store failure whose internals must never
// reach an API client.
const dbErrText = `pq: relation "findings" does not exist`

type leakCase struct {
	name       string
	method     string
	target     string
	body       string
	params     map[string]string
	setup      func(m *mockUsecases)
	invoke     func(h *Handler, w http.ResponseWriter, r *http.Request)
	wantStatus int
	wantCode   string
	wantMsg    string
}

// TestHandlerErrors_DoNotLeakStoreDetail drives every err.Error() 500/4xx
// branch in the triage, assess, finding, and auth handlers with a failing
// store and asserts the client sees only a stable code and a generic
// message — never the underlying error text.
func TestHandlerErrors_DoNotLeakStoreDetail(t *testing.T) {
	dbErr := errors.New(dbErrText)

	cases := []leakCase{
		{
			name:   "triage finding store error",
			method: "PATCH", target: "/api/v1/findings/abc-123",
			body:   `{"analysis_state":"false_positive","reason":"test"}`,
			params: map[string]string{"id": "abc-123"},
			setup: func(m *mockUsecases) {
				m.triageFindingFn = func(_ context.Context, _ usecase.TriageInput) (*usecase.TriageOutput, error) { return nil, dbErr }
			},
			invoke:     func(h *Handler, w http.ResponseWriter, r *http.Request) { h.TriageFinding(w, r) },
			wantStatus: http.StatusInternalServerError, wantCode: "triage_failed",
			wantMsg: "could not update finding analysis state",
		},
		{
			name:   "verify finding store error",
			method: "POST", target: "/api/v1/findings/abc-123/verify",
			body:   `{}`,
			params: map[string]string{"id": "abc-123"},
			setup: func(m *mockUsecases) {
				m.verifyFixFn = func(_ context.Context, _ string) (*usecase.VerifyResponse, error) { return nil, dbErr }
			},
			invoke:     func(h *Handler, w http.ResponseWriter, r *http.Request) { h.VerifyFinding(w, r) },
			wantStatus: http.StatusInternalServerError, wantCode: "verify_failed",
			wantMsg: "could not verify finding fix",
		},
		{
			name:   "bulk triage store error",
			method: "POST", target: "/api/v1/findings/bulk-analysis",
			body: `{"finding_ids":["abc-123"],"analysis_state":"false_positive","reason":"test"}`,
			setup: func(m *mockUsecases) {
				m.bulkTriageFn = func(_ context.Context, _ usecase.BulkTriageInput) ([]usecase.TriageOutput, error) { return nil, dbErr }
			},
			invoke:     func(h *Handler, w http.ResponseWriter, r *http.Request) { h.BulkTriage(w, r) },
			wantStatus: http.StatusInternalServerError, wantCode: "bulk_triage_failed",
			wantMsg: "could not update finding analysis states",
		},
		{
			name:   "gate status store error",
			method: "GET", target: "/api/v1/projects/my-app/gate",
			params: map[string]string{"slug": "my-app"},
			setup: func(m *mockUsecases) {
				m.getGateStatusFn = func(_ context.Context, _ string, _ int16) (*usecase.GateStatusOutput, error) { return nil, dbErr }
			},
			invoke:     func(h *Handler, w http.ResponseWriter, r *http.Request) { h.GetGateStatus(w, r) },
			wantStatus: http.StatusInternalServerError, wantCode: "gate_failed",
			wantMsg: "could not evaluate gate status",
		},
		{
			name:   "finding events store error",
			method: "GET", target: "/api/v1/findings/abc-123/events",
			params: map[string]string{"id": "abc-123"},
			setup: func(m *mockUsecases) {
				m.getFindingEventsFn = func(_ context.Context, _ string, _ []string, _, _ int32) ([]usecase.FindingEvent, error) {
					return nil, dbErr
				}
			},
			invoke:     func(h *Handler, w http.ResponseWriter, r *http.Request) { h.ListFindingEvents(w, r) },
			wantStatus: http.StatusInternalServerError, wantCode: "events_failed",
			wantMsg: "could not list finding events",
		},
		{
			name:   "environments store error",
			method: "GET", target: "/api/v1/projects/my-app/environments",
			params: map[string]string{"slug": "my-app"},
			setup: func(m *mockUsecases) {
				m.listEnvironmentsFn = func(_ context.Context, _ string) ([]usecase.EnvironmentResponse, error) { return nil, dbErr }
			},
			invoke:     func(h *Handler, w http.ResponseWriter, r *http.Request) { h.ListEnvironments(w, r) },
			wantStatus: http.StatusInternalServerError, wantCode: "environments_failed",
			wantMsg: "could not list environments",
		},
		{
			name:   "targets store error",
			method: "GET", target: "/api/v1/projects/my-app/targets",
			params: map[string]string{"slug": "my-app"},
			setup: func(m *mockUsecases) {
				m.listTargetsFn = func(_ context.Context, _ string) ([]usecase.TargetResponse, error) { return nil, dbErr }
			},
			invoke:     func(h *Handler, w http.ResponseWriter, r *http.Request) { h.ListTargets(w, r) },
			wantStatus: http.StatusInternalServerError, wantCode: "targets_failed",
			wantMsg: "could not list targets",
		},
		{
			name:   "artifacts store error",
			method: "GET", target: "/api/v1/projects/my-app/artifacts",
			params: map[string]string{"slug": "my-app"},
			setup: func(m *mockUsecases) {
				m.listArtifactsFn = func(_ context.Context, _ string) ([]usecase.ArtifactResponse, error) { return nil, dbErr }
			},
			invoke:     func(h *Handler, w http.ResponseWriter, r *http.Request) { h.ListArtifacts(w, r) },
			wantStatus: http.StatusInternalServerError, wantCode: "artifacts_failed",
			wantMsg: "could not list artifacts",
		},
		{
			name:   "project stats store error",
			method: "GET", target: "/api/v1/projects/my-app/stats",
			params: map[string]string{"slug": "my-app"},
			setup: func(m *mockUsecases) {
				m.getProjectStatsFn = func(_ context.Context, _ string) (*usecase.ProjectStats, error) { return nil, dbErr }
			},
			invoke:     func(h *Handler, w http.ResponseWriter, r *http.Request) { h.GetProjectStats(w, r) },
			wantStatus: http.StatusInternalServerError, wantCode: "stats_failed",
			wantMsg: "could not compute project statistics",
		},
		{
			name:   "aging store error",
			method: "GET", target: "/api/v1/projects/my-app/aging",
			params: map[string]string{"slug": "my-app"},
			setup: func(m *mockUsecases) {
				m.getAgingFn = func(_ context.Context, _ string) (*usecase.AgingResponse, error) { return nil, dbErr }
			},
			invoke:     func(h *Handler, w http.ResponseWriter, r *http.Request) { h.GetAging(w, r) },
			wantStatus: http.StatusInternalServerError, wantCode: "aging_failed",
			wantMsg: "could not compute aging report",
		},
		{
			name:   "ingest report store error",
			method: "POST", target: "/api/v1/reports",
			body: `{"project":"my-app","scanner":"trivy","raw_data":{"image":"x"}}`,
			setup: func(m *mockUsecases) {
				m.ingestReportFn = func(_ context.Context, _ usecase.IngestReportInput) (*usecase.IngestReportOutput, error) {
					return nil, dbErr
				}
			},
			invoke:     func(h *Handler, w http.ResponseWriter, r *http.Request) { h.IngestReport(w, r) },
			wantStatus: http.StatusUnprocessableEntity, wantCode: "ingest_failed",
			wantMsg: "report ingestion failed",
		},
		{
			name:   "refresh store error",
			method: "POST", target: "/api/v1/auth/refresh",
			body: `{"refresh_token":"tok"}`,
			setup: func(m *mockUsecases) {
				m.refreshFn = func(_ context.Context, _ string) (*usecase.AuthResponse, error) { return nil, dbErr }
			},
			invoke:     func(h *Handler, w http.ResponseWriter, r *http.Request) { h.Refresh(w, r) },
			wantStatus: http.StatusUnauthorized, wantCode: "refresh_failed",
			wantMsg: "invalid or expired refresh token",
		},
		{
			name:   "logout store error",
			method: "POST", target: "/api/v1/auth/logout",
			body: `{"refresh_token":"tok"}`,
			setup: func(m *mockUsecases) {
				m.logoutFn = func(_ context.Context, _ string) error { return dbErr }
			},
			invoke:     func(h *Handler, w http.ResponseWriter, r *http.Request) { h.Logout(w, r) },
			wantStatus: http.StatusInternalServerError, wantCode: "logout_failed",
			wantMsg: "logout failed",
		},
		{
			name:   "create api key store error",
			method: "POST", target: "/api/v1/auth/apikeys",
			body: `{"project":"my-app","name":"ci"}`,
			setup: func(m *mockUsecases) {
				m.createAPIKeyFn = func(_ context.Context, _, _ string, _ *time.Time) (*usecase.APIKeyResponse, error) { return nil, dbErr }
			},
			invoke:     func(h *Handler, w http.ResponseWriter, r *http.Request) { h.CreateAPIKey(w, r) },
			wantStatus: http.StatusUnprocessableEntity, wantCode: "create_failed",
			wantMsg: "could not create API key",
		},
		{
			name:   "revoke api key store error",
			method: "DELETE", target: "/api/v1/auth/apikeys/k1?project=my-app",
			params: map[string]string{"id": "k1"},
			setup: func(m *mockUsecases) {
				m.revokeAPIKeyFn = func(_ context.Context, _, _ string) error { return dbErr }
			},
			invoke:     func(h *Handler, w http.ResponseWriter, r *http.Request) { h.RevokeAPIKey(w, r) },
			wantStatus: http.StatusUnprocessableEntity, wantCode: "revoke_failed",
			wantMsg: "could not revoke API key",
		},
		{
			name:   "create evidence store error",
			method: "POST", target: "/api/v1/findings/abc-123/evidence",
			body:   `{"type":"url","url":"https://example.com/x"}`,
			params: map[string]string{"findingID": "abc-123"},
			setup: func(m *mockUsecases) {
				m.createEvidenceFn = func(_ context.Context, _, _, _, _, _ string) (usecase.EvidenceResponse, error) {
					return usecase.EvidenceResponse{}, dbErr
				}
			},
			invoke:     func(h *Handler, w http.ResponseWriter, r *http.Request) { h.CreateEvidence(w, r) },
			wantStatus: http.StatusInternalServerError, wantCode: "internal_error",
			wantMsg: "could not create evidence",
		},
		{
			name:   "list evidence store error",
			method: "GET", target: "/api/v1/findings/abc-123/evidence",
			params: map[string]string{"findingID": "abc-123"},
			setup: func(m *mockUsecases) {
				m.listEvidenceFn = func(_ context.Context, _ string) ([]usecase.EvidenceResponse, error) { return nil, dbErr }
			},
			invoke:     func(h *Handler, w http.ResponseWriter, r *http.Request) { h.ListEvidence(w, r) },
			wantStatus: http.StatusInternalServerError, wantCode: "internal_error",
			wantMsg: "could not list evidence",
		},
		{
			name:   "delete evidence store error",
			method: "DELETE", target: "/api/v1/evidence/e1",
			params: map[string]string{"evidenceID": "e1"},
			setup: func(m *mockUsecases) {
				m.deleteEvidenceFn = func(_ context.Context, _ string) error { return dbErr }
			},
			invoke:     func(h *Handler, w http.ResponseWriter, r *http.Request) { h.DeleteEvidence(w, r) },
			wantStatus: http.StatusInternalServerError, wantCode: "internal_error",
			wantMsg: "could not delete evidence",
		},
		{
			name:   "upsert reachability store error",
			method: "PATCH", target: "/api/v1/findings/abc-123/reachability",
			body:   `{"state":"not_reachable","evidence":"x"}`,
			params: map[string]string{"findingID": "abc-123"},
			setup: func(m *mockUsecases) {
				m.upsertReachabilityFn = func(_ context.Context, _, _, _, _ string) (*usecase.ReachabilityResponse, error) { return nil, dbErr }
			},
			invoke:     func(h *Handler, w http.ResponseWriter, r *http.Request) { h.UpsertReachability(w, r) },
			wantStatus: http.StatusInternalServerError, wantCode: "internal_error",
			wantMsg: "could not update reachability state",
		},
		{
			name:   "list reachability store error",
			method: "GET", target: "/api/v1/findings/abc-123/reachability",
			params: map[string]string{"findingID": "abc-123"},
			setup: func(m *mockUsecases) {
				m.listReachabilityFn = func(_ context.Context, _ string) ([]usecase.ReachabilityResponse, error) { return nil, dbErr }
			},
			invoke:     func(h *Handler, w http.ResponseWriter, r *http.Request) { h.ListReachability(w, r) },
			wantStatus: http.StatusInternalServerError, wantCode: "internal_error",
			wantMsg: "could not list reachability states",
		},
		{
			name:   "upsert signoff store error",
			method: "PUT", target: "/api/v1/findings/abc-123/signoff",
			body:   `{"status":"approved","comment":"ok"}`,
			params: map[string]string{"findingID": "abc-123"},
			setup: func(m *mockUsecases) {
				m.upsertSignoffFn = func(_ context.Context, _, _, _, _ string) (*usecase.SignoffResponse, error) { return nil, dbErr }
			},
			invoke:     func(h *Handler, w http.ResponseWriter, r *http.Request) { h.UpsertSignoff(w, r) },
			wantStatus: http.StatusInternalServerError, wantCode: "internal_error",
			wantMsg: "could not update signoff",
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockUsecases{}
			tt.setup(mock)
			h := &Handler{usecase: mock}

			req := authRequest(tt.method, tt.target, tt.body)
			if len(tt.params) > 0 {
				for k, v := range tt.params {
					req = addChiURLParam(req, k, v)
				}
			}
			w := httptest.NewRecorder()
			tt.invoke(h, w, req)

			assert.Equal(t, tt.wantStatus, w.Code, "status")
			var body struct {
				Error struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			}
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
			assert.Equal(t, tt.wantCode, body.Error.Code, "code")
			assert.Equal(t, tt.wantMsg, body.Error.Message, "message")
			assert.NotContains(t, w.Body.String(), dbErrText, "underlying error must not leak")
		})
	}
}

// TestBulkTriage_SentinelErrorsKept asserts sentinel errors still map to their
// documented statuses/codes with fixed messages (never err.Error()).
func TestBulkTriage_SentinelErrorsKept(t *testing.T) {
	cases := []struct {
		name       string
		cause      error
		wantStatus int
		wantCode   string
		wantMsg    string
	}{
		{"not found", usecase.ErrFindingNotFound, http.StatusNotFound, "not_found", "one or more findings not found"},
		{"access denied", usecase.ErrProjectAccessDenied, http.StatusForbidden, "project_access_denied", "API key does not have access to this finding"},
		{"reason required", usecase.ErrReasonRequired, http.StatusUnprocessableEntity, "reason_required", "reason is required for this analysis state"},
		{"expiry required", usecase.ErrExpiryRequired, http.StatusUnprocessableEntity, "expiry_required", "expiry is required for accepted_risk and wont_fix"},
		{"invalid state", usecase.ErrInvalidState, http.StatusUnprocessableEntity, "invalid_state", "invalid analysis state"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockUsecases{
				bulkTriageFn: func(_ context.Context, _ usecase.BulkTriageInput) ([]usecase.TriageOutput, error) {
					return nil, fmt.Errorf("finding abc-123: %w", tt.cause)
				},
			}
			h := &Handler{usecase: mock}
			req := authRequest("POST", "/api/v1/findings/bulk-analysis",
				`{"finding_ids":["abc-123"],"analysis_state":"false_positive","reason":"x"}`)
			w := httptest.NewRecorder()
			h.BulkTriage(w, req)

			assert.Equal(t, tt.wantStatus, w.Code)
			var body struct {
				Error struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			}
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
			assert.Equal(t, tt.wantCode, body.Error.Code)
			assert.Equal(t, tt.wantMsg, body.Error.Message)
			assert.NotContains(t, w.Body.String(), "finding abc-123", "finding id prefix must not be echoed")
		})
	}
}

// TestWaiverHandlers_DoNotLeakStoreDetail asserts the waiver handlers
// never echo underlying store errors to the client (M2 regression guard).
func TestWaiverHandlers_DoNotLeakStoreDetail(t *testing.T) {
	dbErr := errors.New(dbErrText)

	cases := []leakCase{
		{
			name:   "create waiver store error",
			method: "POST", target: "/api/v1/projects/my-app/waivers",
			body: `{"name":"test"}`,
			setup: func(m *mockUsecases) {
				m.createWaiverFn = func(_ context.Context, _ usecase.CreateWaiverInput) (*usecase.WaiverResponse, error) {
					return nil, dbErr
				}
			},
			invoke:     func(h *Handler, w http.ResponseWriter, r *http.Request) { h.CreateWaiver(w, r) },
			wantStatus: http.StatusInternalServerError, wantCode: "internal_error",
			wantMsg: "could not create waiver",
		},
		{
			name:   "list waivers store error",
			method: "GET", target: "/api/v1/projects/my-app/waivers",
			setup: func(m *mockUsecases) {
				m.listWaiversFn = func(_ context.Context, _ string) ([]usecase.WaiverResponse, error) { return nil, dbErr }
			},
			invoke:     func(h *Handler, w http.ResponseWriter, r *http.Request) { h.ListWaivers(w, r) },
			wantStatus: http.StatusInternalServerError, wantCode: "internal_error",
			wantMsg: "could not list waivers",
		},
		{
			name:   "get waiver store error",
			method: "GET", target: "/api/v1/projects/my-app/waivers/w1",
			params: map[string]string{"slug": "my-app", "id": "w1"},
			setup: func(m *mockUsecases) {
				m.getWaiverFn = func(_ context.Context, _, _ string) (*usecase.WaiverDetailResponse, error) { return nil, dbErr }
			},
			invoke:     func(h *Handler, w http.ResponseWriter, r *http.Request) { h.GetWaiver(w, r) },
			wantStatus: http.StatusInternalServerError, wantCode: "internal_error",
			wantMsg: "could not get waiver",
		},
		{
			name:   "update waiver store error",
			method: "PUT", target: "/api/v1/projects/my-app/waivers/w1",
			body:   `{"name":"updated"}`,
			params: map[string]string{"slug": "my-app", "id": "w1"},
			setup: func(m *mockUsecases) {
				m.updateWaiverFn = func(_ context.Context, _ usecase.UpdateWaiverInput) (*usecase.WaiverResponse, error) {
					return nil, dbErr
				}
			},
			invoke:     func(h *Handler, w http.ResponseWriter, r *http.Request) { h.UpdateWaiver(w, r) },
			wantStatus: http.StatusInternalServerError, wantCode: "internal_error",
			wantMsg: "could not update waiver",
		},
		{
			name:   "delete waiver store error",
			method: "DELETE", target: "/api/v1/projects/my-app/waivers/w1",
			params: map[string]string{"slug": "my-app", "id": "w1"},
			setup: func(m *mockUsecases) {
				m.deleteWaiverFn = func(_ context.Context, _, _ string) error { return dbErr }
			},
			invoke:     func(h *Handler, w http.ResponseWriter, r *http.Request) { h.DeleteWaiver(w, r) },
			wantStatus: http.StatusInternalServerError, wantCode: "internal_error",
			wantMsg: "could not delete waiver",
		},
		{
			name:   "toggle waiver store error",
			method: "POST", target: "/api/v1/projects/my-app/waivers/w1/toggle",
			params: map[string]string{"slug": "my-app", "id": "w1"},
			setup: func(m *mockUsecases) {
				m.toggleWaiverFn = func(_ context.Context, _, _, _ string) (*usecase.WaiverResponse, error) { return nil, dbErr }
			},
			invoke:     func(h *Handler, w http.ResponseWriter, r *http.Request) { h.ToggleWaiver(w, r) },
			wantStatus: http.StatusInternalServerError, wantCode: "internal_error",
			wantMsg: "could not toggle waiver",
		},
		{
			name:   "list waiver events store error",
			method: "GET", target: "/api/v1/projects/my-app/waivers/w1/events",
			params: map[string]string{"slug": "my-app", "id": "w1"},
			setup: func(m *mockUsecases) {
				m.listWaiverEventsFn = func(_ context.Context, _, _ string) ([]usecase.WaiverEventResp, error) { return nil, dbErr }
			},
			invoke:     func(h *Handler, w http.ResponseWriter, r *http.Request) { h.ListWaiverEvents(w, r) },
			wantStatus: http.StatusInternalServerError, wantCode: "internal_error",
			wantMsg: "could not list waiver events",
		},
		{
			name:   "check waiver match store error",
			method: "POST", target: "/api/v1/projects/my-app/waivers/check-match",
			body:   `{"finding_id":"abc-123"}`,
			params: map[string]string{"slug": "my-app"},
			setup: func(m *mockUsecases) {
				m.checkWaiverMatchFn = func(_ context.Context, _, _ string) (bool, error) { return false, dbErr }
			},
			invoke:     func(h *Handler, w http.ResponseWriter, r *http.Request) { h.CheckWaiverMatch(w, r) },
			wantStatus: http.StatusInternalServerError, wantCode: "internal_error",
			wantMsg: "could not check waiver match",
		},
		{
			name:   "get watcher status store error",
			method: "GET", target: "/api/v1/watcher/status",
			setup: func(m *mockUsecases) {
				m.getWatcherStatusFn = func(_ context.Context) (*usecase.WatcherStatusResponse, error) { return nil, dbErr }
			},
			invoke:     func(h *Handler, w http.ResponseWriter, r *http.Request) { h.GetWatcherStatus(w, r) },
			wantStatus: http.StatusInternalServerError, wantCode: "internal_error",
			wantMsg: "could not get watcher status",
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockUsecases{}
			tt.setup(mock)
			h := &Handler{usecase: mock}

			req := authRequest(tt.method, tt.target, tt.body)
			if len(tt.params) > 0 {
				for k, v := range tt.params {
					req = addChiURLParam(req, k, v)
				}
			}
			w := httptest.NewRecorder()
			tt.invoke(h, w, req)

			assert.Equal(t, tt.wantStatus, w.Code, "status")
			var body struct {
				Error struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			}
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
			assert.Equal(t, tt.wantCode, body.Error.Code, "code")
			assert.Equal(t, tt.wantMsg, body.Error.Message, "message")
			assert.NotContains(t, w.Body.String(), dbErrText, "underlying error must not leak")
		})
	}
}
