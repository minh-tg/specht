package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func challengeOf(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func TestStartLogin_SendsAnS256PKCEChallengeForAVerifierTheURLDoesNotCarry(t *testing.T) {
	a := mustOIDC(t, "https://idp.example.com")

	login := startTestLogin(t, a, "")

	q := mustParseQuery(t, login.url)
	assert.Equal(t, "S256", q.Get("code_challenge_method"))
	require.NotEmpty(t, q.Get("code_challenge"))
	assert.GreaterOrEqual(t, len(q.Get("code_challenge")), 43)
	// The verifier is derived from the cookie secret, which only the browser holds.
	secret := loginSecret(t, a, login)
	verifier := a.pkceVerifier(login.state, secret)
	assert.Equal(t, challengeOf(verifier), q.Get("code_challenge"))
	assert.NotContains(t, login.url, verifier, "the verifier itself never appears in the URL")
	assert.GreaterOrEqual(t, len(verifier), 43, "RFC 7636 minimum verifier length")
}

func TestPKCEVerifierAndNonce_DependOnTheSecretTheStateAndTheServerKey(t *testing.T) {
	a := mustOIDC(t, "https://idp.example.com")
	other := mustOIDC(t, "https://idp.example.com")

	assert.NotEqual(t, a.pkceVerifier("s1", "secret-a"), a.pkceVerifier("s1", "secret-b"),
		"the state alone does not fix the verifier")
	assert.NotEqual(t, a.pkceVerifier("s1", "secret-a"), a.pkceVerifier("s2", "secret-a"))
	assert.Equal(t, a.pkceVerifier("s1", "secret-a"), a.pkceVerifier("s1", "secret-a"), "stable, so a replica can finish the flow")
	assert.NotEqual(t, a.pkceVerifier("s1", "secret-a"), other.pkceVerifier("s1", "secret-a"),
		"a different server key gives a different verifier")
	assert.NotEqual(t, a.nonce("s1", "secret-a"), a.nonce("s1", "secret-b"))
	assert.NotEqual(t, a.nonce("s1", "secret-a"), a.pkceVerifier("s1", "secret-a"), "the nonce never reveals the verifier")
}

func TestStartLogin_StillSendsPKCEWithoutAClientSecret(t *testing.T) {
	a, err := NewOIDCAuthenticator(OIDCConfig{
		ClientID: "c", IssuerURL: "https://idp.example.com", RedirectURI: "http://localhost:8080/callback",
	}, nil)
	require.NoError(t, err)

	login := startTestLogin(t, a, "")

	assert.NotEmpty(t, login.challenge, "a public client depends on PKCE, so it is never skipped")
}

func TestExchangeCode_SendsTheCodeVerifier(t *testing.T) {
	var form url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		form = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at"}`))
	}))
	defer srv.Close()

	_, err := mustOIDC(t, srv.URL).exchangeCode(context.Background(), "the-code", "the-verifier")

	require.NoError(t, err)
	assert.Equal(t, "the-verifier", form.Get("code_verifier"))
	assert.Equal(t, "the-code", form.Get("code"))
}

func TestExchangeCode_OmitsTheVerifierWhenThereIsNone(t *testing.T) {
	var form url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		form = r.PostForm
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	_, err := mustOIDC(t, srv.URL).exchangeCode(context.Background(), "c", "")

	require.NoError(t, err)
	assert.False(t, form.Has("code_verifier"))
}

func TestExchangeCode_OmitsAnEmptyClientSecret(t *testing.T) {
	var form url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		form = r.PostForm
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	a, err := NewOIDCAuthenticator(OIDCConfig{ClientID: "c", IssuerURL: srv.URL, RedirectURI: "http://localhost:8080/cb"}, nil)
	require.NoError(t, err)

	_, err = a.exchangeCode(context.Background(), "c", "v")

	require.NoError(t, err)
	assert.False(t, form.Has("client_secret"), "a public client sends no secret, not an empty one")
	assert.Equal(t, "v", form.Get("code_verifier"))
}

func TestCallback_ProvesPossessionOfTheVerifierBehindTheChallenge(t *testing.T) {
	key := newOIDCTestKey(t)
	prov := newFakeOIDCProvider(t, key)
	a := mustOIDC(t, prov.srv.URL)
	login := startTestLogin(t, a, "")
	prov.idToken = signOIDCIDToken(t, key, prov.srv.URL, "test-client", "oidc-user-1", "oidc@example.com", login.nonce)
	require.NotEmpty(t, login.challenge)

	w, _, _ := callbackResponse(t, a, login)

	require.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, login.challenge, challengeOf(prov.tokenForm.Get("code_verifier")),
		"the verifier sent to the token endpoint must hash to the challenge sent at login")
}

func TestCallback_IgnoresTheOldUnsignedStateCookie(t *testing.T) {
	// Before login state moved into a signed, per-login cookie, the callback
	// accepted any "sso_state" cookie equal to the state in the query. That
	// cookie is now meaningless, so a request that carries only it is refused.
	a := mustOIDC(t, "https://idp.example.com")
	h := a.CallbackHandler(nil)
	req := httptest.NewRequest("GET", "/cb?state=legacy-state.nonce&code=abc", nil)
	req.AddCookie(&http.Cookie{Name: "sso_state", Value: "legacy-state.nonce"})
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestIdentityFromIDToken_NeverSkipsTheNonceCheck(t *testing.T) {
	key := newOIDCTestKey(t)
	prov := newFakeOIDCProvider(t, key)
	a := mustOIDC(t, prov.srv.URL)
	token := signOIDCIDToken(t, key, prov.srv.URL, "test-client", "sub-1", "a@example.com", "the-nonce")

	_, err := a.identityFromIDToken(context.Background(), token, "the-nonce")
	require.NoError(t, err, "control: a matching nonce is accepted")

	_, err = a.identityFromIDToken(context.Background(), token, "")
	assert.ErrorIs(t, err, ErrInvalidCredential, "no expected nonce must mean refusal, not a skipped check")

	_, err = a.identityFromIDToken(context.Background(), token, "another-nonce")
	assert.ErrorIs(t, err, ErrInvalidCredential)
}

func mustParseQuery(t *testing.T, raw string) url.Values {
	t.Helper()
	u, err := url.Parse(raw)
	require.NoError(t, err)
	return u.Query()
}
