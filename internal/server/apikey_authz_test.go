package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xMinhx/specht/internal/auth"
	"github.com/xMinhx/specht/internal/usecase"
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
		{name: "admin-scoped key allowed on admin-gated route", scopes: []string{"admin"}, demands: []string{auth.RoleAdmin}, want: http.StatusOK},
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
	roleMw := RequireRole(auth.RoleAdmin)
	handler := roleMw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest("POST", "/api/v1/projects", nil)
	ctx := auth.ContextWithIdentity(context.Background(), apiKeyIdentity("key-1", "proj-1", "read", "admin"))
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
		ingestReportFn: func(ctx context.Context, input usecase.IngestReportInput) (*usecase.IngestReportOutput, error) {
			return &usecase.IngestReportOutput{ReportID: "rep-1", TotalFindings: 1}, nil
		},
		listAPIKeysFn: func(ctx context.Context, projectSlug string) ([]usecase.APIKeyResponse, error) {
			return []usecase.APIKeyResponse{}, nil
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

// TestRoutes_AdminScopedKeyAllowedOnAdminRoutes is the positive control:
// a key carrying the admin scope is admitted to the project-scoped admin
// routes (the RequireRole admin gates a project API key can legitimately
// exercise). Global operator endpoints (watcher status, scanners) remain
// session-admin-only by design — see TestGlobalStatusEndpoints_AdminOnly.
func TestRoutes_AdminScopedKeyAllowedOnAdminRoutes(t *testing.T) {
	router := apiKeyRouter(t, "key-1", "00000000-0000-0000-0000-000000000001", []string{"admin", "ingest"}, time.Time{})

	keyed := func(method, path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, nil)
		req.Header.Set("Authorization", "Bearer vuln_admin_key")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}

	t.Run("admin key allowed on list api keys", func(t *testing.T) {
		assert.Equal(t, http.StatusOK, keyed("GET", "/api/v1/auth/apikeys?project=my-app").Code)
	})
	t.Run("admin key allowed on create api key", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/auth/apikeys", strings.NewReader(`{"project":"my-app","name":"x"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer vuln_admin_key")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusCreated, w.Code)
	})
}

// TestRoutes_ExpiredAPIKeyRejected_401 drives the production router with an
// expired key: authentication fails and the request never reaches the
// protected handler.
func TestRoutes_ExpiredAPIKeyRejected_401(t *testing.T) {
	router := apiKeyRouter(t, "key-1", "00000000-0000-0000-0000-000000000001", []string{"admin"}, time.Now().Add(-time.Minute))

	req := httptest.NewRequest("GET", "/api/v1/auth/apikeys?project=my-app", nil)
	req.Header.Set("Authorization", "Bearer vuln_expired_key")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}
