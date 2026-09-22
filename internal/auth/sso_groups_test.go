package auth

import (
	"context"
	"crypto/rsa"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseGroupsClaim_Forms(t *testing.T) {
	array := parseGroupsClaim(map[string]any{"groups": []any{"a", "b"}}, "groups")
	assert.Equal(t, []string{"a", "b"}, array)

	single := parseGroupsClaim(map[string]any{"groups": "admins"}, "groups")
	assert.Equal(t, []string{"admins"}, single)

	spaced := parseGroupsClaim(map[string]any{"groups": "a b  c"}, "groups")
	assert.Equal(t, []string{"a", "b", "c"}, spaced)

	assert.Nil(t, parseGroupsClaim(map[string]any{}, "groups"))
	assert.Nil(t, parseGroupsClaim(map[string]any{"groups": nil}, "groups"))
	assert.Nil(t, parseGroupsClaim(map[string]any{"other": []any{"a"}}, "groups"))

	// Non-string members are skipped, never coerced: ambiguous values
	// must not grant elevation.
	mixed := parseGroupsClaim(map[string]any{"groups": []any{"a", 42, map[string]any{}, "b"}}, "groups")
	assert.Equal(t, []string{"a", "b"}, mixed)

	custom := parseGroupsClaim(map[string]any{"roles": []any{"r1"}}, "roles")
	assert.Equal(t, []string{"r1"}, custom, "configurable claim name is honored")
}

func TestParseGroupsClaim_Caps(t *testing.T) {
	many := make([]any, 0, 120)
	for i := 0; i < 120; i++ {
		many = append(many, fmt.Sprintf("g-%d", i))
	}
	assert.Len(t, parseGroupsClaim(map[string]any{"groups": many}, "groups"), maxSSOGroups)

	long := parseGroupsClaim(map[string]any{"groups": []any{strings.Repeat("x", maxSSOGroupLength+1), "ok"}}, "groups")
	assert.Equal(t, []string{"ok"}, long)
}

func TestIsSSOAdmin(t *testing.T) {
	assert.True(t, IsSSOAdmin([]string{"viewers", "admins"}, []string{"admins"}))
	assert.False(t, IsSSOAdmin([]string{"viewers"}, []string{"admins"}))
	assert.False(t, IsSSOAdmin(nil, []string{"admins"}))
	assert.False(t, IsSSOAdmin([]string{"admins"}, nil))
	assert.False(t, IsSSOAdmin([]string{"Admins"}, []string{"admins"}), "matching is exact")
	assert.False(t, IsSSOAdmin([]string{"admins"}, []string{""}), "empty admin entries never match")
}

// oidcGroupClaims carries the per-subject claims signOIDCIDTokenWithGroups
// signs beyond issuer/audience.
type oidcGroupClaims struct {
	sub    string
	email  string
	nonce  string
	groups []string
}

// signOIDCIDTokenWithGroups signs an id_token carrying extra claims
// (groups) for enterprise mapping tests, mirroring signOIDCIDToken.
func signOIDCIDTokenWithGroups(t *testing.T, key *rsa.PrivateKey, issuer, aud string, c oidcGroupClaims) string {
	t.Helper()
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":    issuer,
		"aud":    aud,
		"sub":    c.sub,
		"email":  c.email,
		"iat":    now.Unix(),
		"exp":    now.Add(time.Hour).Unix(),
		"groups": c.groups,
	}
	if c.nonce != "" {
		claims["nonce"] = c.nonce
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = testOIDCKid
	raw, err := tok.SignedString(key)
	require.NoError(t, err)
	return raw
}

func TestOIDC_Callback_ForwardsGroups(t *testing.T) {
	key := newOIDCTestKey(t)
	state, err := GenerateStateToken()
	require.NoError(t, err)
	_, nonce := splitStateNonce(state)

	prov := newFakeOIDCProvider(t, key)
	auth := mustOIDC(t, prov.srv.URL)
	prov.idToken = signOIDCIDTokenWithGroups(t, key, prov.srv.URL, "test-client", oidcGroupClaims{sub: "oidc-user-1", email: "oidc@example.com", nonce: nonce, groups: []string{"idp-admins"}})

	var gotGroups []string
	h := auth.CallbackHandler(func(ctx context.Context, userID, email string, groups []string) (string, error) {
		gotGroups = groups
		return "test-session-token", nil
	})
	req := httptest.NewRequest("GET", "/callback?code=test-code&state="+url.QueryEscape(state), nil)
	req.AddCookie(&http.Cookie{Name: "sso_state", Value: state})
	w := httptest.NewRecorder()
	h(w, req)

	require.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, []string{"idp-admins"}, gotGroups)
}

func TestOIDC_Callback_MergesUserinfoGroups(t *testing.T) {
	key := newOIDCTestKey(t)
	state, err := GenerateStateToken()
	require.NoError(t, err)
	_, nonce := splitStateNonce(state)

	prov := newFakeOIDCProvider(t, key)
	prov.userGroups = `["idp-viewers"]`
	auth := mustOIDC(t, prov.srv.URL)
	prov.idToken = signOIDCIDTokenWithGroups(t, key, prov.srv.URL, "test-client", oidcGroupClaims{sub: "oidc-user-1", email: "oidc@example.com", nonce: nonce, groups: []string{"idp-admins"}})

	var gotGroups []string
	h := auth.CallbackHandler(func(ctx context.Context, userID, email string, groups []string) (string, error) {
		gotGroups = groups
		return "test-session-token", nil
	})
	req := httptest.NewRequest("GET", "/callback?code=test-code&state="+url.QueryEscape(state), nil)
	req.AddCookie(&http.Cookie{Name: "sso_state", Value: state})
	w := httptest.NewRecorder()
	h(w, req)

	require.Equal(t, http.StatusFound, w.Code)
	assert.ElementsMatch(t, []string{"idp-admins", "idp-viewers"}, gotGroups)
}
