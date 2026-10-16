package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/usecase"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// apiKeyIdentity builds a project-scoped API-key identity carrying the given
// permission scopes, the shape the (fixed) APIKeyAuthenticator produces.
func apiKeyIdentity(userID, projectID string, scopes ...string) *auth.Identity {
	return &auth.Identity{
		UserID:    userID,
		ProjectID: projectID,
		IsAPIKey:  true,
		Scopes:    scopes,
	}
}

// --- AuthMiddleware / Authenticator wiring (H3) ---

// TestAuthMiddleware_ExpiredAPIKeyRejected_401 pins the H3 fix at the
// request boundary: presenting an expired API key must fail authentication
// (401), never reach the protected handler.
func TestAuthMiddleware_ExpiredAPIKeyRejected_401(t *testing.T) {
	apiKeyAuth := auth.NewAPIKeyAuthenticator(func(ctx context.Context, keyHash string) (string, string, []string, time.Time, error) {
		return "key-1", "project-1", []string{"ingest"}, time.Now().Add(-time.Minute), nil
	})
	handler := AuthMiddleware(testJWTAuth, apiKeyAuth)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest("GET", "/api/v1/projects", nil)
	req.Header.Set("Authorization", "Bearer vuln_expiredkeymaterial")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestAuthMiddleware_ActiveAPIKeyIdentityCarriesScopes verifies the identity
// minted from a live key reaches the handler with its scopes intact, so
// downstream middleware can enforce them.
func TestAuthMiddleware_ActiveAPIKeyIdentityCarriesScopes(t *testing.T) {
	apiKeyAuth := auth.NewAPIKeyAuthenticator(func(ctx context.Context, keyHash string) (string, string, []string, time.Time, error) {
		return "key-1", "project-1", []string{"ingest"}, time.Time{}, nil
	})
	var got *auth.Identity
	handler := AuthMiddleware(testJWTAuth, apiKeyAuth)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = auth.ContextIdentity(r.Context())
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest("GET", "/api/v1/projects", nil)
	req.Header.Set("Authorization", "Bearer vuln_activkeymaterial")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	require.NotNil(t, got)
	assert.Equal(t, []string{"ingest"}, got.Scopes)
}

// --- RequireRole scope enforcement (H3) ---

// TestRequireRole_APIKeyRequiresScope pins the H3 fix in RequireRole: an
// API key is admitted to a role-gated route only when it carries the scope
// that corresponds to the demanded role. A key that merely authenticates
// (pre-fix behavior: unconditional bypass) is now denied 403.
func TestRequireRole_APIKeyRequiresScope(t *testing.T) {
	tests := []struct {
		name    string
		scopes  []string
		demands []string
		want    int
	}{
		{name: "ingest key denied on admin-gated route", scopes: []string{"ingest"}, demands: []string{auth.RoleAdmin}, want: http.StatusForbidden},
		{name: "read key denied on admin-gated route", scopes: []string{"read"}, demands: []string{auth.RoleAdmin}, want: http.StatusForbidden},
		{name: "ingest+read key denied on admin-gated route", scopes: []string{"ingest", "read"}, demands: []string{auth.RoleAdmin}, want: http.StatusForbidden},
		{name: "no key scope covers an admin-gated route", scopes: []string{"ingest", "read", "admin"}, demands: []string{auth.RoleAdmin}, want: http.StatusForbidden},
		{name: "read key allowed on a viewer-gated route", scopes: []string{"read"}, demands: []string{auth.RoleViewer}, want: http.StatusOK},
		{name: "key without required scope denied", scopes: []string{"ingest"}, demands: []string{"editor", "viewer"}, want: http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			roleMw := RequireRole(tt.demands...)
			handler := roleMw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			req := httptest.NewRequest("POST", "/api/v1/projects", nil)
			ctx := auth.ContextWithIdentity(context.Background(), apiKeyIdentity("key-1", "proj-1", tt.scopes...))
			req = req.WithContext(ctx)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			assert.Equal(t, tt.want, w.Code)
		})
	}
}

// TestRequireRole_APIKeyScopesNotRequiredForReadRole keeps the door open for
// read-role gates that map to an explicit key scope, while documenting that
// an API key is never admitted to a role gate it has no scope for.
func TestRequireRole_APIKeyScopesNotRequiredForReadRole(t *testing.T) {
	roleMw := RequireRole(auth.RoleViewer)
	handler := roleMw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest("GET", "/api/v1/projects", nil)
	ctx := auth.ContextWithIdentity(context.Background(), apiKeyIdentity("key-1", "proj-1", "read"))
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// --- End-to-end routing (H3): NewRouter with the fixed lookup ---

// apiKeyRouter builds the real router with an API-key lookup that resolves
// key material to a fixed principal (scopes + expiry). The mock use-cases
// serve project-boundary lookups (GetProject) and the ingest/list-key calls
// the exercised handlers make.
func apiKeyRouter(t *testing.T, userID, projectID string, scopes []string, exp time.Time) http.Handler {
	t.Helper()
	mock := &mockUsecases{
		getProjectFn: func(ctx context.Context, slug string) (*usecase.ProjectResponse, error) {
			return &usecase.ProjectResponse{ID: projectID, Slug: slug}, nil
		},
		listFindingsFn: func(ctx context.Context, projectSlug string, filter usecase.FindingFilter, limit, offset int32) ([]usecase.FindingResponse, int64, error) {
			return []usecase.FindingResponse{}, 0, nil
		},
		ingestReportFn: func(ctx context.Context, input usecase.IngestReportInput) (*usecase.IngestReportOutput, error) {
			return &usecase.IngestReportOutput{ReportID: "rep-1", TotalFindings: 1}, nil
		},
		listAPIKeysFn: func(ctx context.Context, projectSlug string) ([]usecase.APIKeyResponse, error) {
			return []usecase.APIKeyResponse{}, nil
		},
		createWaiverFn: func(ctx context.Context, input usecase.CreateWaiverInput) (*usecase.WaiverResponse, error) {
			return &usecase.WaiverResponse{Name: input.Name}, nil
		},
		createAPIKeyFn: func(ctx context.Context, projectSlug, name string, expiresAt *time.Time) (*usecase.APIKeyResponse, error) {
			return &usecase.APIKeyResponse{ID: "k1", Name: name, KeyPrefix: "vuln_abc"}, nil
		},
	}
	return NewRouter(RouterConfig{
		Usecases: mock,
		JWTAuth:  testJWTAuth,
		APIKeyLookup: func(ctx context.Context, keyHash string) (string, string, []string, time.Time, error) {
			return userID, projectID, scopes, exp, nil
		},
	})
}

// TestRoutes_APIKeyScopeEnforcement drives the production router: an
// ingest-scoped key must be able to POST reports for its project but must be
// denied every admin-gated management route (create/list/revoke keys,
// create project).
func TestRoutes_APIKeyScopeEnforcement(t *testing.T) {
	router := apiKeyRouter(t, "key-1", "00000000-0000-0000-0000-000000000001", []string{"ingest"}, time.Time{})

	keyed := func(method, path string, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer vuln_ci_ingest_key")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}

	t.Run("ingest scope POST /reports is allowed", func(t *testing.T) {
		body := `{"project":"my-app","scanner":"trivy","raw_data":{"Results":[]}}`
		w := keyed("POST", "/api/v1/reports", body)
		assert.Equal(t, http.StatusCreated, w.Code, "ingest-scoped key must ingest: %s", w.Body.String())
	})

	t.Run("ingest key denied on create project", func(t *testing.T) {
		w := keyed("POST", "/api/v1/projects", `{"name":"x","slug":"x"}`)
		assert.Equal(t, http.StatusForbidden, w.Code, "ingest-scoped key must not create projects")
	})

	t.Run("ingest key denied on create api key", func(t *testing.T) {
		w := keyed("POST", "/api/v1/auth/apikeys", `{"project":"my-app","name":"x"}`)
		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("ingest key denied on list api keys", func(t *testing.T) {
		w := keyed("GET", "/api/v1/auth/apikeys?project=my-app", "")
		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("ingest key denied on revoke api key", func(t *testing.T) {
		w := keyed("DELETE", "/api/v1/auth/apikeys/00000000-0000-0000-0000-000000000099?project=my-app", "")
		assert.Equal(t, http.StatusForbidden, w.Code)
	})
}

func TestRoutes_APIKeyScopesSeparateReadAndIngest(t *testing.T) {
	const projectID = "00000000-0000-0000-0000-000000000001"
	request := func(scopes []string, method, path, body string) *httptest.ResponseRecorder {
		router := apiKeyRouter(t, "key-1", projectID, scopes, time.Time{})
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer vuln_scoped_key")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}

	t.Run("ingest-only key cannot read findings", func(t *testing.T) {
		w := request([]string{auth.ScopeIngest}, http.MethodGet, "/api/v1/projects/my-app/findings", "")
		assert.Equal(t, http.StatusForbidden, w.Code)
	})
	t.Run("read key can read findings", func(t *testing.T) {
		w := request([]string{auth.ScopeRead}, http.MethodGet, "/api/v1/projects/my-app/findings", "")
		assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
	})
	t.Run("read key cannot ingest reports", func(t *testing.T) {
		w := request([]string{auth.ScopeRead}, http.MethodPost, "/api/v1/reports", `{"project":"my-app","scanner":"trivy","raw_data":{"Results":[]}}`)
		assert.Equal(t, http.StatusForbidden, w.Code)
	})
	t.Run("ingest-only key cannot create waivers", func(t *testing.T) {
		w := request([]string{auth.ScopeIngest}, http.MethodPost, "/api/v1/projects/my-app/waivers", `{"name":"temporary"}`)
		assert.Equal(t, http.StatusForbidden, w.Code)
	})
	t.Run("ingest and read key cannot create a project waiver", func(t *testing.T) {
		w := request([]string{auth.ScopeIngest, auth.ScopeRead}, http.MethodPost, "/api/v1/projects/my-app/waivers", `{"name":"temporary"}`)
		assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	})
}

// TestRoutes_AdminScopedKeyRefusedEverywhere: the API mints only ingest and
// read keys, so a key whose stored scopes include admin (settable only in
// the database) must fail authentication on every route, with the same
// answer as an unknown key, instead of passing a route guard and failing
// deeper down.
func TestRoutes_AdminScopedKeyRefusedEverywhere(t *testing.T) {
	const projectID = "00000000-0000-0000-0000-000000000001"
	router := apiKeyRouter(t, "key-1", projectID, []string{"admin", "ingest", "read"}, time.Time{})

	for _, tc := range []struct{ method, path string }{
		{"GET", "/api/v1/projects/my-app/findings"},
		{"GET", "/api/v1/projects/my-app/gate"},
		{"GET", "/api/v1/findings/00000000-0000-0000-0000-000000000099"},
		{"GET", "/api/v1/auth/apikeys?project=my-app"},
		{"POST", "/api/v1/reports"},
		{"POST", "/api/v1/projects/my-app/waivers"},
	} {
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(`{}`))
		req.Header.Set("Authorization", "Bearer vuln_admin_scope_key")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusUnauthorized, w.Code, "%s %s: %s", tc.method, tc.path, w.Body.String())
		assert.Contains(t, w.Body.String(), `"invalid_token"`, "same shape as an unknown key")
	}
}

// TestRoutes_KeyRefusedOnProjectManagementRoutes: no key scope covers project
// management, so even a key holding every scope the API mints gets 403 there.
func TestRoutes_KeyRefusedOnProjectManagementRoutes(t *testing.T) {
	router := apiKeyRouter(t, "key-1", "00000000-0000-0000-0000-000000000001", []string{"ingest", "read"}, time.Time{})
	keyed := func(method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer vuln_ci_key")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}
	t.Run("list api keys", func(t *testing.T) {
		assert.Equal(t, http.StatusForbidden, keyed("GET", "/api/v1/auth/apikeys?project=my-app", "").Code)
	})
	t.Run("create api key", func(t *testing.T) {
		assert.Equal(t, http.StatusForbidden, keyed("POST", "/api/v1/auth/apikeys", `{"project":"my-app","name":"x"}`).Code)
	})
	t.Run("create a platform project", func(t *testing.T) {
		assert.Equal(t, http.StatusForbidden, keyed("POST", "/api/v1/projects", `{"name":"x","slug":"x"}`).Code)
	})
	t.Run("inspect global retention state", func(t *testing.T) {
		assert.Equal(t, http.StatusForbidden, keyed("GET", "/api/v1/admin/retention/preview?days=30", "").Code)
	})
	t.Run("modify global policy templates", func(t *testing.T) {
		assert.Equal(t, http.StatusForbidden, keyed("DELETE", "/api/v1/policy-templates/00000000-0000-0000-0000-000000000099", "").Code)
	})
}

// TestRoutes_ExpiredAPIKeyRejected_401 drives the production router with an
// expired key: authentication fails and the request never reaches the
// protected handler.
func TestRoutes_ExpiredAPIKeyRejected_401(t *testing.T) {
	router := apiKeyRouter(t, "key-1", "00000000-0000-0000-0000-000000000001", []string{"ingest", "read"}, time.Now().Add(-time.Minute))

	req := httptest.NewRequest("GET", "/api/v1/auth/apikeys?project=my-app", nil)
	req.Header.Set("Authorization", "Bearer vuln_expired_key")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}
