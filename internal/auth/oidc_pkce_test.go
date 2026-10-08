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

func TestLoginURL_SendsAnS256PKCEChallengeDerivedFromTheState(t *testing.T) {
	a := mustOIDC(t, "https://idp.example.com")
	state, err := GenerateStateToken()
	require.NoError(t, err)

	q := mustParseQuery(t, a.LoginURL(state))

	assert.Equal(t, "S256", q.Get("code_challenge_method"))
	verifier := a.pkceVerifier(state)
	require.NotEmpty(t, verifier)
	assert.Equal(t, challengeOf(verifier), q.Get("code_challenge"))
	assert.NotContains(t, a.LoginURL(state), verifier, "the verifier itself never appears in the URL")
	assert.GreaterOrEqual(t, len(verifier), 43, "RFC 7636 minimum verifier length")
}

func TestPKCEVerifier_IsUniquePerStateAndDependsOnTheClientSecret(t *testing.T) {
	a := mustOIDC(t, "https://idp.example.com")
	other, err := NewOIDCAuthenticator(OIDCConfig{
		ClientID: "test-client", ClientSecret: "another-secret", IssuerURL: "https://idp.example.com",
		RedirectURI: "http://localhost:8080/callback",
	}, nil)
	require.NoError(t, err)

	assert.NotEqual(t, a.pkceVerifier("s1.n1"), a.pkceVerifier("s2.n2"))
	assert.Equal(t, a.pkceVerifier("s1.n1"), a.pkceVerifier("s1.n1"), "stable, so any replica can finish the flow")
	assert.NotEqual(t, a.pkceVerifier("s1.n1"), other.pkceVerifier("s1.n1"),
		"someone who sees the state but not the client secret cannot compute the verifier")
}

func TestLoginURL_OmitsPKCEWithoutAClientSecret(t *testing.T) {
	a, err := NewOIDCAuthenticator(OIDCConfig{
		ClientID: "c", IssuerURL: "https://idp.example.com", RedirectURI: "http://localhost:8080/callback",
	}, nil)
	require.NoError(t, err)

	q := mustParseQuery(t, a.LoginURL("csrf.nonce"))

	assert.Empty(t, q.Get("code_challenge"), "an empty secret would make the verifier guessable, so PKCE is skipped")
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

func TestCallback_ProvesPossessionOfTheVerifierBehindTheChallenge(t *testing.T) {
	key := newOIDCTestKey(t)
	state, err := GenerateStateToken()
	require.NoError(t, err)
	_, nonce := splitStateNonce(state)
	prov := newFakeOIDCProvider(t, key)
	prov.idToken = signOIDCIDToken(t, key, prov.srv.URL, "test-client", "oidc-user-1", "oidc@example.com", nonce)
	a := mustOIDC(t, prov.srv.URL)
	challenge := mustParseQuery(t, a.LoginURL(state)).Get("code_challenge")
	require.NotEmpty(t, challenge)

	w, _, _ := callbackResponse(t, a, state)

	require.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, challenge, challengeOf(prov.tokenForm.Get("code_verifier")),
		"the verifier sent to the token endpoint must hash to the challenge sent at login")
}

func TestCallback_RefusesAStateWithoutANonce(t *testing.T) {
	a := mustOIDC(t, "https://idp.example.com")
	h := a.CallbackHandler(nil)
	req := httptest.NewRequest("GET", "/cb?state=legacy-state&code=abc", nil)
	req.AddCookie(&http.Cookie{Name: "sso_state", Value: "legacy-state"})
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code, "the nonce is mandatory; there is no legacy no-nonce path")
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
