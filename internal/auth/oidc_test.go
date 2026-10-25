package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
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
	seedEndpoints(a)
	return a
}

// seedEndpoints fills the discovery cache with fixed endpoints under the
// issuer, as if its discovery document had been fetched, so tests about the
// rest of the flow need neither a discovery document nor a reachable issuer.
// oidc_discovery_test.go covers discovery itself.
func seedEndpoints(a *OIDCAuthenticator) {
	base := strings.TrimSuffix(a.cfg.IssuerURL, "/")
	a.mu.Lock()
	defer a.mu.Unlock()
	a.meta = providerMetadata{
		Issuer:                a.cfg.IssuerURL,
		AuthorizationEndpoint: base + "/oauth/authorize",
		TokenEndpoint:         base + "/oauth/token",
		UserinfoEndpoint:      base + "/userinfo",
		JWKSURI:               base + "/.well-known/jwks.json",
	}
	a.metaOK = true
	a.metaExpiry = time.Now().Add(time.Hour)
}

func TestOIDC_SSRFAddressChecks(t *testing.T) {
	for _, raw := range []string{"127.0.0.1", "10.0.0.1", "169.254.1.1", "192.168.1.1", "::1", "fc00::1", "2001:db8::1"} {
		t.Run(raw, func(t *testing.T) {
			assert.True(t, isBlockedIP(net.ParseIP(raw)))
		})
	}
	assert.False(t, isBlockedIP(net.ParseIP("8.8.8.8")))
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

func TestOIDC_JWKSResponseLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"keys":[]}` + strings.Repeat(" ", maxJWKSBodyBytes)))
	}))
	defer server.Close()
	a := mustOIDC(t, server.URL)
	err := a.fetchJWKS(context.Background())
	require.Error(t, err)
	assert.ErrorContains(t, err, "exceeds")
}

func TestOIDC_StartLogin_BuildsTheAuthorizationURL(t *testing.T) {
	a := mustOIDC(t, "https://example.com")

	login := startTestLogin(t, a, "")

	assert.Contains(t, login.url, "https://example.com/oauth/authorize")
	assert.Contains(t, login.url, "client_id=test-client")
	assert.Contains(t, login.url, "redirect_uri=http")
	assert.Contains(t, login.url, "response_type=code")
	assert.Contains(t, login.url, "scope=openid+email+profile")
	assert.Contains(t, login.url, "state="+url.QueryEscape(login.state))
	assert.NotEmpty(t, login.nonce)
}

func TestOIDC_CallbackHandler_MissingCode(t *testing.T) {
	a := mustOIDC(t, "https://example.com")

	h := a.CallbackHandler(func(ctx context.Context, _ SSOClaims) (string, error) {
		return "token", nil
	})
	req := httptest.NewRequest("GET", "/api/v1/auth/sso/callback", nil)
	w := httptest.NewRecorder()
	h(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestOIDC_CallbackHandler_MissingState(t *testing.T) {
	a := mustOIDC(t, "https://example.com")

	h := a.CallbackHandler(func(ctx context.Context, _ SSOClaims) (string, error) {
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

	h := a.CallbackHandler(func(ctx context.Context, _ SSOClaims) (string, error) {
		return "token", nil
	})
	real := startTestLogin(t, a, "")
	req := httptest.NewRequest("GET", "/callback?code=test-code&state=attacker-state", nil)
	for _, c := range real.cookies {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	h(w, req)

	// A state with no cookie of its own must be refused.
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
func signOIDCIDToken(t *testing.T, key *rsa.PrivateKey, issuer, aud, sub, email, nonce string, extra ...jwt.MapClaims) string {
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
	for _, e := range extra {
		for k, v := range e {
			claims[k] = v
		}
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
	t           *testing.T
	srv         *httptest.Server
	idToken     string
	omitIDToken bool
	userSub     string
	userGroups  string
	// userEmailVerified, when non-nil, is sent as the userinfo email_verified
	// claim exactly as given (bool, string, ...).
	userEmailVerified any
	// tokenForm is the form body of the most recent token request.
	tokenForm url.Values
}

func writeFakeOIDCResponse(t *testing.T, w http.ResponseWriter, format string, args ...any) {
	t.Helper()
	if _, err := fmt.Fprintf(w, format, args...); err != nil {
		t.Errorf("write fake OIDC response: %v", err)
	}
}

func newFakeOIDCProvider(t *testing.T, key *rsa.PrivateKey) *fakeOIDCProvider {
	t.Helper()
	p := &fakeOIDCProvider{t: t, userSub: "oidc-user-1"}
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/oauth/token":
			_ = r.ParseForm()
			p.tokenForm = r.PostForm
			if p.omitIDToken {
				writeFakeOIDCResponse(t, w, `{"access_token":"acc-test","token_type":"Bearer"}`)
			} else {
				writeFakeOIDCResponse(t, w, `{"access_token":"acc-test","token_type":"Bearer","id_token":%q}`, p.idToken)
			}
		case "/userinfo":
			info := map[string]any{"sub": p.userSub, "email": "oidc@example.com"}
			if p.userEmailVerified != nil {
				info["email_verified"] = p.userEmailVerified
			}
			if p.userGroups != "" {
				info["groups"] = json.RawMessage(p.userGroups)
			}
			body, err := json.Marshal(info)
			require.NoError(t, err)
			writeFakeOIDCResponse(t, w, "%s", body)
		case "/.well-known/jwks.json":
			writeFakeOIDCResponse(t, w, "%s", jwksBody(t, &key.PublicKey))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(p.srv.Close)
	return p
}

// callbackClaims drives the SSO callback for a login started with
// startTestLogin, with its cookies as the browser would send them, and returns
// the recorder plus the claims the token issuer saw.
func callbackClaims(t *testing.T, a *OIDCAuthenticator, login testLogin) (*httptest.ResponseRecorder, SSOClaims) {
	t.Helper()
	var got SSOClaims
	h := a.CallbackHandler(func(ctx context.Context, claims SSOClaims) (string, error) {
		got = claims
		return "test-session-token", nil
	})
	w := httptest.NewRecorder()
	h(w, login.callbackRequest("test-code"))
	return w, got
}

// callbackResponse is callbackClaims reduced to the subject and email.
func callbackResponse(t *testing.T, a *OIDCAuthenticator, login testLogin) (*httptest.ResponseRecorder, string, string) {
	t.Helper()
	w, claims := callbackClaims(t, a, login)
	return w, claims.Subject, claims.Email
}

func TestOIDC_Callback_NonceRoundTrip(t *testing.T) {
	// End-to-end: the login sends the provider a nonce, the provider signs an
	// id_token carrying it, and the callback accepts it and derives the same
	// identity.
	key := newOIDCTestKey(t)
	prov := newFakeOIDCProvider(t, key)
	auth := mustOIDC(t, prov.srv.URL)
	login := startTestLogin(t, auth, "")
	require.NotEmpty(t, login.nonce, "the authorization request must carry a nonce")
	prov.idToken = signOIDCIDToken(t, key, prov.srv.URL, "test-client", "oidc-user-1", "oidc@example.com", login.nonce)

	w, gotUserID, gotEmail := callbackResponse(t, auth, login)
	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "oidc-user-1", gotUserID)
	assert.Equal(t, "oidc@example.com", gotEmail)
}

func TestOIDC_Callback_RejectsNonceMismatch(t *testing.T) {
	// The provider (or an attacker in the redirect) returns an id_token whose
	// nonce does not match the one bound to the state cookie: rejected.
	key := newOIDCTestKey(t)
	prov := newFakeOIDCProvider(t, key)
	prov.idToken = signOIDCIDToken(t, key, prov.srv.URL, "test-client", "oidc-user-1", "oidc@example.com", "attacker-nonce")
	auth := mustOIDC(t, prov.srv.URL)
	auth.cfg.AllowUserInfoOnly = true

	w, _, _ := callbackResponse(t, auth, startTestLogin(t, auth, ""))
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "identity extraction failed")
}

func TestOIDC_Callback_RejectsUserInfoSubMismatch(t *testing.T) {
	// A userinfo endpoint answering with a different subject than the verified
	// id_token must not be trusted: the identity must be refused.
	key := newOIDCTestKey(t)
	prov := newFakeOIDCProvider(t, key)
	prov.userSub = "someone-else"
	auth := mustOIDC(t, prov.srv.URL)
	auth.cfg.AllowUserInfoOnly = true
	login := startTestLogin(t, auth, "")
	prov.idToken = signOIDCIDToken(t, key, prov.srv.URL, "test-client", "oidc-user-1", "oidc@example.com", login.nonce)

	w, _, _ := callbackResponse(t, auth, login)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "identity extraction failed")
}

func TestOIDC_Callback_RejectsAbsentIDTokenByDefault(t *testing.T) {
	key := newOIDCTestKey(t)
	prov := newFakeOIDCProvider(t, key)
	prov.omitIDToken = true
	auth := mustOIDC(t, prov.srv.URL)

	w, gotUserID, _ := callbackResponse(t, auth, startTestLogin(t, auth, ""))
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Empty(t, gotUserID, "userinfo-only response must not issue a session by default")
}

func TestOIDC_Callback_AllowsAbsentIDTokenWhenExplicitlyEnabled(t *testing.T) {
	key := newOIDCTestKey(t)
	prov := newFakeOIDCProvider(t, key)
	prov.omitIDToken = true
	auth := mustOIDC(t, prov.srv.URL)
	auth.cfg.AllowUserInfoOnly = true

	w, gotUserID, gotEmail := callbackResponse(t, auth, startTestLogin(t, auth, ""))
	assert.Equal(t, "oidc-user-1", gotUserID)
	assert.Equal(t, "oidc@example.com", gotEmail)
	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "/#sso_code=test-session-token", w.Header().Get("Location"))
}

func TestOIDC_Callback_RejectsMalformedIDTokenWhenUserInfoOnlyEnabled(t *testing.T) {
	key := newOIDCTestKey(t)
	prov := newFakeOIDCProvider(t, key)
	prov.idToken = "not-a-jwt"
	auth := mustOIDC(t, prov.srv.URL)
	auth.cfg.AllowUserInfoOnly = true

	w, gotUserID, _ := callbackResponse(t, auth, startTestLogin(t, auth, ""))
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Empty(t, gotUserID, "opt-in applies only when the token is absent")
}

func TestOIDC_Callback_DeliversTokenInFragment(t *testing.T) {
	// The session token must be delivered to the SPA as a URL fragment (which
	// is never sent to the server or leaked via Referer), not as an httpOnly
	// cookie that nothing in the stack ever reads.
	key := newOIDCTestKey(t)
	prov := newFakeOIDCProvider(t, key)
	auth := mustOIDC(t, prov.srv.URL)
	login := startTestLogin(t, auth, "")
	prov.idToken = signOIDCIDToken(t, key, prov.srv.URL, "test-client", "oidc-user-1", "oidc@example.com", login.nonce)
	w, gotUserID, gotEmail := callbackResponse(t, auth, login)
	assert.Equal(t, "oidc-user-1", gotUserID)
	assert.Equal(t, "oidc@example.com", gotEmail)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "/#sso_code=test-session-token", w.Header().Get("Location"))
	for _, c := range w.Result().Cookies() {
		assert.NotEqual(t, "token", c.Name, "callback must not set a session cookie")
	}
}

func TestOIDC_Callback_PreservesValidatedReturnPath(t *testing.T) {
	key := newOIDCTestKey(t)
	prov := newFakeOIDCProvider(t, key)
	a := mustOIDC(t, prov.srv.URL)
	login := startTestLogin(t, a, "/projects/demo?tab=members")
	prov.idToken = signOIDCIDToken(t, key, prov.srv.URL, "test-client", "oidc-user-1", "oidc@example.com", login.nonce)

	w, _, _ := callbackResponse(t, a, login)
	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "/projects/demo?tab=members#sso_code=test-session-token", w.Header().Get("Location"))
	for _, cookie := range w.Result().Cookies() {
		assert.False(t, cookie.Name == ssoStateCookieName(login.state) && cookie.MaxAge < 0,
			"the login cookie, which holds the return path, stays until the exchange redeems the code")
	}
}

func TestOIDC_Callback_RefusesAnUnsafeReturnPath(t *testing.T) {
	key := newOIDCTestKey(t)
	prov := newFakeOIDCProvider(t, key)
	a := mustOIDC(t, prov.srv.URL)
	login := startTestLogin(t, a, "//evil.example/steal")
	prov.idToken = signOIDCIDToken(t, key, prov.srv.URL, "test-client", "oidc-user-1", "oidc@example.com", login.nonce)

	w, _, _ := callbackResponse(t, a, login)

	assert.Equal(t, "/#sso_code=test-session-token", w.Header().Get("Location"))
}

func TestOIDC_GenerateStateToken_IsRandomAndPublic(t *testing.T) {
	first, err := GenerateStateToken()
	require.NoError(t, err)
	second, err := GenerateStateToken()
	require.NoError(t, err)

	assert.NotEqual(t, first, second)
	assert.GreaterOrEqual(t, len(first), 43, "256 bits, base64url")
	assert.NotContains(t, first, ".", "the state carries no second half: nothing is derived from it alone")
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
		writeFakeOIDCResponse(t, w, "%s", jwksBody(t, &key.PublicKey))
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

func TestOIDC_Callback_NotProvisionedIsForbidden(t *testing.T) {
	// The issuer gate rejects unknown IdP subjects: the callback must
	// answer 403 with a generic message, never leaking account existence.
	key := newOIDCTestKey(t)
	prov := newFakeOIDCProvider(t, key)
	prov.userSub = "unknown-sub"
	a := mustOIDC(t, prov.srv.URL)
	login := startTestLogin(t, a, "")
	prov.idToken = signOIDCIDToken(t, key, prov.srv.URL, "test-client", "unknown-sub", "stranger@evil.example", login.nonce)

	h := a.CallbackHandler(func(ctx context.Context, claims SSOClaims) (string, error) {
		assert.Equal(t, "unknown-sub", claims.Subject)
		// The fake provider answers a fixed userinfo email; the 403 below
		// is what this test pins, not the address value.
		return "", ErrSSONotProvisioned
	})
	w := httptest.NewRecorder()
	h(w, login.callbackRequest("test-code"))

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "sso account not provisioned")
}

func TestOIDC_Callback_InvalidProviderEmailIsForbiddenAndNamed(t *testing.T) {
	// The issuer refuses an address the server cannot accept. The callback
	// answers 403 and says the provider's address is the problem, which
	// discloses nothing about local accounts.
	key := newOIDCTestKey(t)
	prov := newFakeOIDCProvider(t, key)
	prov.userSub = "odd-sub"
	a := mustOIDC(t, prov.srv.URL)
	login := startTestLogin(t, a, "")
	prov.idToken = signOIDCIDToken(t, key, prov.srv.URL, "test-client", "odd-sub", "ada@example.com", login.nonce)

	h := a.CallbackHandler(func(ctx context.Context, claims SSOClaims) (string, error) {
		return "", ErrSSOInvalidEmail
	})
	w := httptest.NewRecorder()
	h(w, login.callbackRequest("test-code"))

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "email address this server cannot accept")
	assert.NotContains(t, w.Body.String(), "sso account not provisioned")
}
