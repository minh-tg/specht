package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mustOIDC builds an OIDC authenticator for tests, failing on the constructor
// error path that L4's issuer validation introduces.
func mustOIDC(t *testing.T, issuerURL string) *OIDCAuthenticator {
	t.Helper()
	a, err := NewOIDCAuthenticator(OIDCConfig{
		ClientID:     "test-client",
		ClientSecret: "secret",
		IssuerURL:    issuerURL,
		RedirectURI:  "http://localhost:8080/callback",
	}, nil)
	require.NoError(t, err)
	return a
}

func TestOIDC_Authenticate_NonOIDCToken(t *testing.T) {
	a := mustOIDC(t, "https://example.com")

	// Tokens that don't start with "oidc:" should fall through (ErrNotApplicable).
	ident, err := a.Authenticate(context.Background(), "some-other-token")
	assert.Nil(t, ident)
	assert.ErrorIs(t, err, ErrNotApplicable)
}

func TestOIDC_Authenticate_RejectsOIDCBearer(t *testing.T) {
	a := mustOIDC(t, "https://example.com")

	// The OIDC authenticator is only wired to the SSO login/callback flow; it
	// is never part of the bearer-auth chain. Treating "oidc:<code>" as a
	// bearer credential would put a one-time code into Authorization headers
	// and logs, so it must fall through like any other unrecognized token.
	ident, err := a.Authenticate(context.Background(), "oidc:anything")
	assert.Nil(t, ident)
	assert.ErrorIs(t, err, ErrNotApplicable)
	assert.NotErrorIs(t, err, ErrInvalidCredential)
}

func TestOIDC_RejectsInsecureIssuer(t *testing.T) {
	// The client secret is POSTed to issuer-derived endpoints. Any issuer
	// that is not HTTPS (and not a loopback dev/testing address) must be
	// refused at construction, before the secret can ever be sent in clear.
	for _, raw := range []string{"", "example.com", "http://example.com", "http://accounts.google.com", "http://192.168.1.10:8080"} {
		t.Run(raw, func(t *testing.T) {
			a, err := NewOIDCAuthenticator(OIDCConfig{
				ClientID:     "test-client",
				ClientSecret: "secret",
				IssuerURL:    raw,
				RedirectURI:  "http://localhost:8080/callback",
			}, nil)
			assert.Nil(t, a)
			require.Error(t, err)
			assert.ErrorContains(t, err, "must use https")
		})
	}

	// HTTPS and loopback plain-HTTP issuers are acceptable (httptest and
	// local development providers run over http://127.0.0.1).
	for _, raw := range []string{"https://example.com", "https://accounts.google.com", "http://localhost:9000", "http://127.0.0.1:9000", "http://[::1]:9000"} {
		t.Run(raw, func(t *testing.T) {
			a, err := NewOIDCAuthenticator(OIDCConfig{
				ClientID:     "test-client",
				ClientSecret: "secret",
				IssuerURL:    raw,
				RedirectURI:  "http://localhost:8080/callback",
			}, nil)
			require.NoError(t, err)
			require.NotNil(t, a)
		})
	}
}

func TestOIDC_LoginURL(t *testing.T) {
	a := mustOIDC(t, "https://example.com")

	u := a.LoginURL("csrf-state")
	assert.Contains(t, u, "https://example.com/oauth/authorize")
	assert.Contains(t, u, "client_id=test-client")
	assert.Contains(t, u, "redirect_uri=http")
	assert.Contains(t, u, "response_type=code")
	assert.Contains(t, u, "scope=openid+email+profile")
	assert.Contains(t, u, "state=csrf-state")
	// A legacy/hand-rolled state without a nonce half must not gain one.
	assert.NotContains(t, u, "nonce=")
}

func TestOIDC_CallbackHandler_MissingCode(t *testing.T) {
	a := mustOIDC(t, "https://example.com")

	h := a.CallbackHandler(func(userID, email string) (string, error) {
		return "token", nil
	})
	req := httptest.NewRequest("GET", "/api/v1/auth/sso/callback", nil)
	w := httptest.NewRecorder()
	h(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestOIDC_CallbackHandler_MissingState(t *testing.T) {
	a := mustOIDC(t, "https://example.com")

	h := a.CallbackHandler(func(userID, email string) (string, error) {
		return "token", nil
	})
	req := httptest.NewRequest("GET", "/callback?code=test-code", nil)
	w := httptest.NewRecorder()
	h(w, req)

	// No state cookie was set, so the callback must be refused.
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestOIDC_CallbackHandler_StateMismatch(t *testing.T) {
	a := mustOIDC(t, "https://example.com")

	h := a.CallbackHandler(func(userID, email string) (string, error) {
		return "token", nil
	})
	req := httptest.NewRequest("GET", "/callback?code=test-code&state=attacker-state", nil)
	req.AddCookie(&http.Cookie{Name: "sso_state", Value: "real-state"})
	w := httptest.NewRecorder()
	h(w, req)

	// A state that does not match the cookie must be refused.
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// --- L4 helpers: fake OIDC provider and RSA-signed id_tokens ---

const testOIDCKid = "test-kid-1"

// newOIDCTestKey returns a fresh 2048-bit RSA key for signing id_tokens and
// serving the matching JWKS.
func newOIDCTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return key
}

// jwksBody renders a single-RSA-key JWKS document for pub.
func jwksBody(t *testing.T, pub *rsa.PublicKey) string {
	t.Helper()
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	return fmt.Sprintf(`{"keys":[{"kty":"RSA","kid":%q,"alg":"RS256","use":"sig","n":%q,"e":%q}]}`, testOIDCKid, n, e)
}

// signOIDCIDToken signs an id_token with the given key, kid, issuer, audience,
// subject, and optional nonce.
func signOIDCIDToken(t *testing.T, key *rsa.PrivateKey, issuer, aud, sub, email, nonce string) string {
	t.Helper()
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":   issuer,
		"aud":   aud,
		"sub":   sub,
		"email": email,
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = testOIDCKid
	raw, err := tok.SignedString(key)
	require.NoError(t, err)
	return raw
}

// fakeOIDCProvider is a configurable OIDC provider: token endpoint, userinfo
// endpoint (with the configured subject), and the JWKS for key.
type fakeOIDCProvider struct {
	t              *testing.T
	srv            *httptest.Server
	idToken        string
	userSub        string
	userSubChanger func() string
}

func newFakeOIDCProvider(t *testing.T, key *rsa.PrivateKey) *fakeOIDCProvider {
	t.Helper()
	p := &fakeOIDCProvider{t: t, userSub: "oidc-user-1"}
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/oauth/token":
			fmt.Fprintf(w, `{"access_token":"acc-test","token_type":"Bearer","id_token":%q}`, p.idToken)
		case "/userinfo":
			sub := p.userSub
			fmt.Fprintf(w, `{"sub":%q,"email":%q}`, sub, "oidc@example.com")
		case "/.well-known/jwks.json":
			fmt.Fprint(w, jwksBody(t, &key.PublicKey))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(p.srv.Close)
	return p
}

// callbackResponse drives the SSO callback with state echoed both in the query
// and the cookie (as the router does) and returns the recorder plus the
// identity the token issuer saw.
func callbackResponse(t *testing.T, a *OIDCAuthenticator, state string) (*httptest.ResponseRecorder, string, string) {
	t.Helper()
	var gotUserID, gotEmail string
	h := a.CallbackHandler(func(userID, email string) (string, error) {
		gotUserID, gotEmail = userID, email
		return "test-session-token", nil
	})
	req := httptest.NewRequest("GET", "/callback?code=test-code&state="+url.QueryEscape(state), nil)
	req.AddCookie(&http.Cookie{Name: "sso_state", Value: state})
	w := httptest.NewRecorder()
	h(w, req)
	return w, gotUserID, gotEmail
}

func TestOIDC_Callback_NonceRoundTrip(t *testing.T) {
	// End-to-end: the login flow mints a compound state, LoginURL forwards its
	// nonce half to the provider, the provider signs an id_token carrying that
	// nonce, and the callback accepts it and derives the same identity.
	key := newOIDCTestKey(t)
	state, err := GenerateStateToken()
	require.NoError(t, err)
	_, nonce := splitStateNonce(state)
	require.NotEmpty(t, nonce, "generated state must carry a nonce half")

	a := mustOIDC(t, "https://example.com")
	login := a.LoginURL(state)
	assert.Contains(t, login, "state="+url.QueryEscape(state))
	assert.Contains(t, login, "nonce="+url.QueryEscape(nonce), "LoginURL must forward the state-bound nonce")

	// Now run the callback against a provider that echoes that nonce.
	prov := newFakeOIDCProvider(t, key)
	prov.idToken = signOIDCIDToken(t, key, prov.srv.URL, "test-client", "oidc-user-1", "oidc@example.com", nonce)
	auth := mustOIDC(t, prov.srv.URL)

	w, gotUserID, gotEmail := callbackResponse(t, auth, state)
	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "oidc-user-1", gotUserID)
	assert.Equal(t, "oidc@example.com", gotEmail)
}

func TestOIDC_Callback_RejectsNonceMismatch(t *testing.T) {
	// The provider (or an attacker in the redirect) returns an id_token whose
	// nonce does not match the one bound to the state cookie: rejected.
	key := newOIDCTestKey(t)
	state, err := GenerateStateToken()
	require.NoError(t, err)

	prov := newFakeOIDCProvider(t, key)
	prov.idToken = signOIDCIDToken(t, key, prov.srv.URL, "test-client", "oidc-user-1", "oidc@example.com", "attacker-nonce")
	auth := mustOIDC(t, prov.srv.URL)

	w, _, _ := callbackResponse(t, auth, state)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "identity extraction failed")
}

func TestOIDC_Callback_RejectsUserInfoSubMismatch(t *testing.T) {
	// A userinfo endpoint answering with a different subject than the verified
	// id_token must not be trusted: the identity must be refused.
	key := newOIDCTestKey(t)
	state, err := GenerateStateToken()
	require.NoError(t, err)
	_, nonce := splitStateNonce(state)

	prov := newFakeOIDCProvider(t, key)
	prov.idToken = signOIDCIDToken(t, key, prov.srv.URL, "test-client", "oidc-user-1", "oidc@example.com", nonce)
	prov.userSub = "someone-else"
	auth := mustOIDC(t, prov.srv.URL)

	w, _, _ := callbackResponse(t, auth, state)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "identity extraction failed")
}

func TestOIDC_Callback_DeliversTokenInFragment(t *testing.T) {
	// Minimal fake provider: the token endpoint returns an access token with
	// no id_token, so identity extraction falls back to the userinfo endpoint.
	key := newOIDCTestKey(t)
	prov := newFakeOIDCProvider(t, key)
	prov.idToken = "" // access-token-only response
	auth := mustOIDC(t, prov.srv.URL)

	state := "csrf-state"
	w, gotUserID, gotEmail := callbackResponse(t, auth, state)
	assert.Equal(t, "oidc-user-1", gotUserID)
	assert.Equal(t, "oidc@example.com", gotEmail)

	// The session token must be delivered to the SPA as a URL fragment (which
	// is never sent to the server or leaked via Referer), not as an httpOnly
	// cookie that nothing in the stack ever reads.
	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "/#sso_token=test-session-token", w.Header().Get("Location"))
	for _, c := range w.Result().Cookies() {
		assert.NotEqual(t, "token", c.Name, "callback must not set a session cookie")
	}
}

func TestOIDC_GenerateStateToken_CompoundShape(t *testing.T) {
	state, err := GenerateStateToken()
	require.NoError(t, err)

	csrf, nonce := splitStateNonce(state)
	assert.NotEmpty(t, csrf, "csrf half must be non-empty")
	assert.NotEmpty(t, nonce, "nonce half must be non-empty")
	assert.NotEqual(t, csrf, nonce, "halves must be independent random values")
	assert.NotContains(t, csrf, ".", "csrf half must not contain the separator")
	assert.NotContains(t, nonce, ".", "nonce half must not contain the separator")
}

func TestOIDC_Callback_JWKSRefreshSingleflight(t *testing.T) {
	// Key rotation: an unknown kid triggers a JWKS fetch; concurrent lookups
	// must coalesce into a single provider hit (singleflight), then all
	// resolve to the rotated key.
	key := newOIDCTestKey(t)
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		time.Sleep(50 * time.Millisecond) // widen the race window
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, jwksBody(t, &key.PublicKey))
	}))
	defer srv.Close()

	a := mustOIDC(t, srv.URL)
	// Force a stale cache so the lookup path below must refresh.
	a.mu.Lock()
	a.keyCache["stale-kid"] = &key.PublicKey
	a.keyExpiry = time.Now().Add(-time.Minute)
	a.mu.Unlock()

	const n = 8
	results := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() {
			_, err := a.fetchJWKKey(context.Background(), testOIDCKid)
			results <- err
		}()
	}
	for i := 0; i < n; i++ {
		require.NoError(t, <-results)
	}
	assert.Equal(t, 1, hits, "concurrent key misses must share one JWKS fetch")
}
