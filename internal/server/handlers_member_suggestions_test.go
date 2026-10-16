package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/usecase"
)

func (m *mockUsecases) SuggestProjectMembers(context.Context, string, string, bool) ([]usecase.MemberSuggestion, error) {
	return nil, fmt.Errorf("unexpected call to SuggestProjectMembers")
}

// suggestMock answers member suggestions on top of the shared mock and
// records what the handler passed on.
type suggestMock struct {
	*mockUsecases
	calls           int
	query           string
	directoryClosed bool
	result          []usecase.MemberSuggestion
	err             error
}

func (m *suggestMock) SuggestProjectMembers(_ context.Context, _, query string, directoryClosed bool) ([]usecase.MemberSuggestion, error) {
	m.calls++
	m.query, m.directoryClosed = query, directoryClosed
	return m.result, m.err
}

func newSuggestMock() *suggestMock {
	return &suggestMock{mockUsecases: memberErrorMock(), result: []usecase.MemberSuggestion{}}
}

func suggestRequest(t *testing.T, router http.Handler, token, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func TestSuggestProjectMembers_ReturnsTheUsecaseResult(t *testing.T) {
	mock := newSuggestMock()
	mock.result = []usecase.MemberSuggestion{{UserID: "u1", Email: "ada@acme.example", DisplayName: "Ada"}}
	router := NewRouter(RouterConfig{Usecases: mock, JWTAuth: testJWTAuth, RegistrationDisabled: true})

	w := suggestRequest(t, router, makeTestToken(t, auth.RoleViewer), "/api/v1/projects/my-app/member-suggestions?q=ada%25")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.JSONEq(t, `[{"user_id":"u1","email":"ada@acme.example","display_name":"Ada"}]`, w.Body.String())
	assert.Equal(t, "ada%", mock.query, "the raw query goes to the usecase")
}

func TestSuggestProjectMembers_EmptyIsAnEmptyList(t *testing.T) {
	router := NewRouter(RouterConfig{Usecases: newSuggestMock(), JWTAuth: testJWTAuth, RegistrationDisabled: true})
	w := suggestRequest(t, router, makeTestToken(t, auth.RoleViewer), "/api/v1/projects/my-app/member-suggestions?q=ad")
	require.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `[]`, w.Body.String())
}

// The handler and the capabilities endpoint read the same router setting, so
// the UI never offers suggestions the server would refuse to give.
func TestSuggestProjectMembers_RegistrationFlagMatchesCapabilities(t *testing.T) {
	for _, disabled := range []bool{true, false} {
		t.Run(fmt.Sprintf("registration disabled=%v", disabled), func(t *testing.T) {
			mock := newSuggestMock()
			router := NewRouter(RouterConfig{Usecases: mock, JWTAuth: testJWTAuth, RegistrationDisabled: disabled})

			w := suggestRequest(t, router, "", "/api/v1/capabilities")
			require.Equal(t, http.StatusOK, w.Code)
			var caps struct {
				Registration struct {
					Enabled bool `json:"enabled"`
				} `json:"registration"`
			}
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &caps))

			w = suggestRequest(t, router, makeTestToken(t, auth.RoleViewer), "/api/v1/projects/my-app/member-suggestions?q=ada")
			require.Equal(t, http.StatusOK, w.Code)
			require.Equal(t, 1, mock.calls)
			assert.Equal(t, caps.Registration.Enabled, mock.directoryClosed)
		})
	}
}

// With registration closed, the directory stays closed too when SSO is on and
// accepts emails the identity provider did not verify: such a user can hold an
// account under an address they chose. The option is inert without SSO.
func TestSuggestProjectMembers_UnverifiedSSOEmailClosesTheDirectory(t *testing.T) {
	for _, tc := range []struct {
		name       string
		oidc       bool
		unverified bool
		wantClosed bool
	}{
		{"sso on, unverified emails allowed", true, true, true},
		{"sso on, verified emails only", true, false, false},
		{"sso off, option set", false, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mock := newSuggestMock()
			cfg := RouterConfig{Usecases: mock, JWTAuth: testJWTAuth, RegistrationDisabled: true, SSOAllowUnverifiedEmail: tc.unverified}
			if tc.oidc {
				cfg.OIDCEnabled, cfg.OIDC = true, testOIDC(t)
			}
			w := suggestRequest(t, NewRouter(cfg), makeTestToken(t, auth.RoleViewer), "/api/v1/projects/my-app/member-suggestions?q=ada")
			require.Equal(t, http.StatusOK, w.Code, w.Body.String())
			require.Equal(t, 1, mock.calls)
			assert.Equal(t, tc.wantClosed, mock.directoryClosed)
		})
	}
}

// A missing project and an outsider get exactly what the add-member route
// gives them, so the new route reveals nothing the old one hides.
func TestSuggestProjectMembers_AccessMatchesTheAddMemberRoute(t *testing.T) {
	for _, tc := range []struct {
		name       string
		role       string
		setup      func(*suggestMock)
		wantStatus int
	}{
		{"missing project for an instance admin", auth.RoleAdmin, func(m *suggestMock) {
			m.getProjectFn = func(context.Context, string) (*usecase.ProjectResponse, error) { return nil, errors.New("not found") }
		}, http.StatusNotFound},
		{"missing project for a member", auth.RoleViewer, func(m *suggestMock) {
			m.getProjectFn = func(context.Context, string) (*usecase.ProjectResponse, error) { return nil, errors.New("not found") }
		}, http.StatusForbidden},
		{"outsider", auth.RoleViewer, func(m *suggestMock) {
			m.isProjectMemberFn = func(context.Context, string, string) (bool, error) { return false, nil }
		}, http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mock := newSuggestMock()
			tc.setup(mock)
			router := NewRouter(RouterConfig{Usecases: mock, JWTAuth: testJWTAuth, RegistrationDisabled: true})
			token := makeTestToken(t, tc.role)

			suggest := suggestRequest(t, router, token, "/api/v1/projects/my-app/member-suggestions?q=ada")
			req := httptest.NewRequest(http.MethodPost, "/api/v1/projects/my-app/members",
				strings.NewReader(`{"email":"ada@acme.example","role":"member"}`))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+token)
			add := httptest.NewRecorder()
			router.ServeHTTP(add, req)

			assert.Equal(t, tc.wantStatus, suggest.Code, suggest.Body.String())
			assert.Equal(t, add.Code, suggest.Code)
			assert.JSONEq(t, add.Body.String(), suggest.Body.String())
			assert.Zero(t, mock.calls, "the usecase is not reached")
		})
	}
}

func TestSuggestProjectMembers_ErrorMapping(t *testing.T) {
	for _, tc := range []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
	}{
		{"not a manager", usecase.ErrProjectAccessDenied, http.StatusForbidden, "project_access_denied"},
		{"query too long", usecase.ErrSuggestionQueryTooLong, http.StatusBadRequest, "invalid_query"},
		{"query not usable text", usecase.ErrSuggestionQueryInvalid, http.StatusBadRequest, "invalid_query"},
		{"store failure", errors.New("connection reset"), http.StatusInternalServerError, "internal_error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mock := newSuggestMock()
			mock.err = tc.err
			router := NewRouter(RouterConfig{Usecases: mock, JWTAuth: testJWTAuth, RegistrationDisabled: true})
			w := suggestRequest(t, router, makeTestToken(t, auth.RoleViewer), "/api/v1/projects/my-app/member-suggestions?q=ada")
			assert.Equal(t, tc.wantStatus, w.Code)
			assert.Equal(t, tc.wantCode, errorCodeOf(t, w))
		})
	}
}

func TestSuggestProjectMembers_SessionOnly(t *testing.T) {
	mock := newSuggestMock()
	router := NewRouter(RouterConfig{
		Usecases: mock,
		JWTAuth:  testJWTAuth,
		APIKeyLookup: func(context.Context, string) (string, string, []string, time.Time, error) {
			return "key-owner", "00000000-0000-0000-0000-000000000001", []string{auth.ScopeIngest, auth.ScopeRead}, time.Time{}, nil
		},
		RegistrationDisabled: true,
	})

	w := suggestRequest(t, router, "", "/api/v1/projects/my-app/member-suggestions?q=ada")
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	w = suggestRequest(t, router, "vuln_project_admin_key", "/api/v1/projects/my-app/member-suggestions?q=ada")
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Zero(t, mock.calls)
}

func TestSuggestProjectMembers_RateLimitedPerUserWithoutTheGlobalSwitch(t *testing.T) {
	mock := newSuggestMock()
	router := NewRouter(RouterConfig{Usecases: mock, JWTAuth: testJWTAuth, RegistrationDisabled: true})
	path := "/api/v1/projects/my-app/member-suggestions?q=ada"
	busy := makeTestTokenFor(t, "busy-user")

	for i := range 10 {
		w := suggestRequest(t, router, busy, path)
		require.Equal(t, http.StatusOK, w.Code, "request %d is inside the burst", i+1)
	}
	w := suggestRequest(t, router, busy, path)
	assert.Equal(t, http.StatusTooManyRequests, w.Code)
	assert.NotEmpty(t, w.Header().Get("Retry-After"))

	w = suggestRequest(t, router, makeTestTokenFor(t, "other-user"), path)
	assert.Equal(t, http.StatusOK, w.Code, "another person has their own bucket")
}

func makeTestTokenFor(t *testing.T, userID string) string {
	t.Helper()
	a, err := auth.NewJWTAuthenticator(testJWTSecret)
	require.NoError(t, err)
	tok, err := a.CreateToken(userID, userID+"@example.com", auth.RoleViewer, 0)
	require.NoError(t, err)
	return tok
}
