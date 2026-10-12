package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type capabilitiesBody struct {
	Registration struct {
		Enabled bool `json:"enabled"`
	} `json:"registration"`
	SSO struct {
		Enabled   bool   `json:"enabled"`
		LoginPath string `json:"login_path"`
	} `json:"sso"`
	Version string `json:"version"`
}

func getCapabilities(t *testing.T, cfg RouterConfig) (*httptest.ResponseRecorder, capabilitiesBody) {
	t.Helper()
	cfg.Usecases = &mockUsecases{}
	cfg.JWTAuth = testJWTAuth
	req := httptest.NewRequest("GET", "/api/v1/capabilities", nil)
	req.RemoteAddr = "192.0.2.90:1234"
	w := httptest.NewRecorder()
	NewRouter(cfg).ServeHTTP(w, req)
	var body capabilitiesBody
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body), w.Body.String())
	return w, body
}

func TestCapabilities_DefaultsToOpenRegistrationAndNoSSO(t *testing.T) {
	w, body := getCapabilities(t, RouterConfig{})

	require.Equal(t, http.StatusOK, w.Code)
	assert.True(t, body.Registration.Enabled)
	assert.False(t, body.SSO.Enabled)
	assert.Empty(t, body.SSO.LoginPath, "no login path is advertised while SSO is off")
	assert.NotEmpty(t, body.Version)
}

func TestCapabilities_ReflectsRegistrationAndSSO(t *testing.T) {
	_, body := getCapabilities(t, RouterConfig{RegistrationDisabled: true, OIDCEnabled: true, OIDC: testOIDC(t)})

	assert.False(t, body.Registration.Enabled)
	assert.True(t, body.SSO.Enabled)
	assert.Equal(t, "/api/v1/auth/sso/login", body.SSO.LoginPath)
}

func TestCapabilities_SSOFlagWithoutAProviderStaysOff(t *testing.T) {
	_, body := getCapabilities(t, RouterConfig{OIDCEnabled: true})

	assert.False(t, body.SSO.Enabled, "the route is only registered with a provider, so the page must not offer it")
}

func TestCapabilities_IsPublicAndShortCached(t *testing.T) {
	w, _ := getCapabilities(t, RouterConfig{})

	assert.Equal(t, "public, max-age=60", w.Header().Get("Cache-Control"))
	assert.NotContains(t, w.Body.String(), "issuer", "no provider detail leaks")
}
