package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// strictIdP is a fake provider that behaves like a strict OIDC server:
// /oauth/authorize records the code_challenge and nonce for the code it
// issues, and /oauth/token refuses the code unless the S256 of code_verifier
// equals that challenge. Each code is single use at the provider.
type strictIdP struct {
	srv *httptest.Server

	mu          sync.Mutex
	codes       map[string]strictGrant
	redemptions int
}

type strictGrant struct {
	challenge string
	nonce     string
	sub       string
}

func newStrictIdP(t *testing.T) *strictIdP {
	t.Helper()
	key := newOIDCTestKey(t)
	p := &strictIdP{codes: map[string]strictGrant{}}
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			_ = r.ParseForm()
			p.mu.Lock()
			grant, ok := p.codes[r.PostForm.Get("code")]
			delete(p.codes, r.PostForm.Get("code"))
			p.mu.Unlock()
			if !ok {
				http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
				return
			}
			sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
			if r.PostForm.Get("code_verifier") == "" || base64.RawURLEncoding.EncodeToString(sum[:]) != grant.challenge {
				http.Error(w, `{"error":"invalid_grant","error_description":"PKCE verification failed"}`, http.StatusBadRequest)
				return
			}
			p.mu.Lock()
			p.redemptions++
			p.mu.Unlock()
			now := time.Now()
			tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
				"iss": p.srv.URL, "aud": "test-client", "sub": grant.sub, "email": grant.sub + "@corp.example",
				"email_verified": true, "nonce": grant.nonce, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
			})
			tok.Header["kid"] = testOIDCKid
			idt, err := tok.SignedString(key)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"access_token":"acc-%s","token_type":"Bearer","id_token":%q}`, grant.sub, idt)
		case "/userinfo":
			sub := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer acc-")
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"sub":%q,"email":"%s@corp.example","email_verified":true}`, sub, sub)
		case "/.well-known/jwks.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, jwksBody(t, &key.PublicKey))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(p.srv.Close)
	return p
}

// authorize plays the browser reaching the IdP with the URL Specht built and
// the user consenting. It returns the code the IdP puts in the callback.
func (p *strictIdP) authorize(t *testing.T, l testLogin, sub string) string {
	t.Helper()
	q := mustParseQuery(t, l.url)
	require.Equal(t, "S256", q.Get("code_challenge_method"))
	code := "code-" + sub + "-" + l.state[:6]
	p.mu.Lock()
	p.codes[code] = strictGrant{challenge: q.Get("code_challenge"), nonce: q.Get("nonce"), sub: sub}
	p.mu.Unlock()
	return code
}

func (p *strictIdP) redeemed() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.redemptions
}

// authFor builds an authenticator against the IdP; mutate may change the config.
func (p *strictIdP) authFor(t *testing.T, mutate ...func(*OIDCConfig)) *OIDCAuthenticator {
	t.Helper()
	cfg := OIDCConfig{
		ClientID: "test-client", ClientSecret: "secret", IssuerURL: p.srv.URL,
		RedirectURI: "http://localhost:8080/api/v1/auth/sso/callback",
	}
	for _, m := range mutate {
		m(&cfg)
	}
	a, err := NewOIDCAuthenticator(cfg, nil)
	require.NoError(t, err)
	return a
}

// finish runs the callback with the given cookies and reports the response and
// the subjects the session issuer was asked to sign in.
func finish(t *testing.T, a *OIDCAuthenticator, l testLogin, code string, cookies ...*http.Cookie) (*httptest.ResponseRecorder, []string) {
	t.Helper()
	var subjects []string
	h := a.CallbackHandler(func(_ context.Context, c SSOClaims) (string, error) {
		subjects = append(subjects, c.Subject)
		return "exchange-code-for-" + c.Subject, nil
	})
	w := httptest.NewRecorder()
	h(w, l.callbackRequestWith(code, cookies...))
	return w, subjects
}

// A stolen, unredeemed authorization code plus the state that sat next to it
// in the callback URL used to be enough to sign in as the victim from another
// browser: the verifier and nonce came from the public state. They now come
// from a secret in the victim's own cookie.
func TestCallback_ReplayedFromAnotherBrowserIsRefused(t *testing.T) {
	idp := newStrictIdP(t)
	a := idp.authFor(t)

	victim := startTestLogin(t, a, "")
	code := idp.authorize(t, victim, "victim-sub")
	attacker := startTestLogin(t, a, "") // the attacker's own, legitimate login
	require.Len(t, attacker.cookies, 1)
	ownCookie := attacker.cookies[0]

	t.Run("no cookie at all", func(t *testing.T) {
		w, subjects := finish(t, a, victim, code)
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Empty(t, subjects)
	})
	t.Run("the attacker's own cookie under the attacker's name", func(t *testing.T) {
		w, subjects := finish(t, a, victim, code, ownCookie)
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Empty(t, subjects)
	})
	t.Run("the attacker's own cookie value moved under the victim's cookie name", func(t *testing.T) {
		forged := &http.Cookie{Name: ssoStateCookieName(victim.state), Value: ownCookie.Value}
		w, subjects := finish(t, a, victim, code, forged)
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Empty(t, subjects)
	})
	t.Run("the old unsigned cookie holding the public state", func(t *testing.T) {
		w, subjects := finish(t, a, victim, code, &http.Cookie{Name: "sso_state", Value: victim.state})
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Empty(t, subjects)
	})
	t.Run("a cookie the attacker signs with a key of their own", func(t *testing.T) {
		mine := idp.authFor(t, func(c *OIDCConfig) { c.StateKey = []byte("attacker-controlled-key-0123456789") })
		l := ssoLogin{secret: "known-to-attacker", expires: time.Now().Add(time.Minute), returnPath: "/"}
		forged := &http.Cookie{Name: ssoStateCookieName(victim.state), Value: mine.sealLogin(victim.state, l)}
		w, subjects := finish(t, a, victim, code, forged)
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Empty(t, subjects)
	})
	assert.Zero(t, idp.redeemed(), "no refused request reached the token endpoint")

	t.Run("the victim's own browser still completes the login", func(t *testing.T) {
		w, subjects := finish(t, a, victim, code, victim.cookies...)
		require.Equal(t, http.StatusFound, w.Code)
		assert.Equal(t, []string{"victim-sub"}, subjects)
		assert.Equal(t, "/#sso_code=exchange-code-for-victim-sub", w.Header().Get("Location"))
		assert.Equal(t, 1, idp.redeemed())
	})
}

// The code the callback mints is handed the browser binding of the login, so
// the exchange can later tell which browser may redeem it.
func TestCallback_IssuesTheCodeWithTheLoginsBrowserBinding(t *testing.T) {
	idp := newStrictIdP(t)
	a := idp.authFor(t)
	login := startTestLogin(t, a, "")
	code := idp.authorize(t, login, "user-1")

	var issued SSOClaims
	h := a.CallbackHandler(func(_ context.Context, c SSOClaims) (string, error) {
		issued = c
		return "exchange-code", nil
	})
	w := httptest.NewRecorder()
	h(w, login.callbackRequestWith(code, login.cookies...))

	require.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, BrowserBinding(loginSecret(t, a, login)), issued.BrowserBinding)
	assert.NotContains(t, issued.BrowserBinding, loginSecret(t, a, login), "the binding is a hash, not the secret")
}

func TestCallback_NormalFlowWorksWithAndWithoutAClientSecret(t *testing.T) {
	for name, mutate := range map[string]func(*OIDCConfig){
		"confidential client": func(*OIDCConfig) {},
		"public client":       func(c *OIDCConfig) { c.ClientSecret = "" },
	} {
		t.Run(name, func(t *testing.T) {
			idp := newStrictIdP(t)
			a := idp.authFor(t, mutate)
			login := startTestLogin(t, a, "/projects/demo?tab=members")
			code := idp.authorize(t, login, "user-1")

			w, subjects := finish(t, a, login, code, login.cookies...)

			require.Equal(t, http.StatusFound, w.Code, w.Body.String())
			assert.Equal(t, []string{"user-1"}, subjects)
			assert.Equal(t, "/projects/demo?tab=members#sso_code=exchange-code-for-user-1", w.Header().Get("Location"))
		})
	}
}

func TestCallback_TheLoginCookieIsSingleUse(t *testing.T) {
	idp := newStrictIdP(t)
	a := idp.authFor(t)
	login := startTestLogin(t, a, "")
	code := idp.authorize(t, login, "user-1")

	first, _ := finish(t, a, login, code, login.cookies...)
	require.Equal(t, http.StatusFound, first.Code)
	jar := browserJar{}
	jar.apply(login.cookies)
	jar.apply(first.Result().Cookies())

	second, subjects := finish(t, a, login, code, jar.list()...)

	assert.Equal(t, http.StatusBadRequest, second.Code, "the cookie was cleared with the first callback")
	assert.Empty(t, subjects)
}

func TestCallback_RefusesAnExpiredOrTamperedCookie(t *testing.T) {
	idp := newStrictIdP(t)
	a := idp.authFor(t)
	login := startTestLogin(t, a, "/projects/demo")
	code := idp.authorize(t, login, "user-1")
	cookie := login.cookies[0]
	parts := strings.Split(cookie.Value, ".")
	require.Len(t, parts, 5, "version, secret, expiry, return path, signature")

	with := func(i int, v string) *http.Cookie {
		p := append([]string(nil), parts...)
		p[i] = v
		return &http.Cookie{Name: cookie.Name, Value: strings.Join(p, ".")}
	}
	cases := map[string]*http.Cookie{
		"another secret":             with(1, "AAAA"),
		"a later expiry":             with(2, "99999999999"),
		"another return path":        with(3, base64.RawURLEncoding.EncodeToString([]byte("/admin"))),
		"another version":            with(0, "v2"),
		"a stripped signature":       {Name: cookie.Name, Value: strings.Join(parts[:4], ".")},
		"a truncated signature":      with(4, parts[4][:10]),
		"an empty value":             {Name: cookie.Name, Value: ""},
		"a signature of another key": {Name: cookie.Name, Value: strings.Join(parts[:4], ".") + "." + strings.Repeat("A", 43)},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			w, subjects := finish(t, a, login, code, c)
			assert.Equal(t, http.StatusBadRequest, w.Code)
			assert.Empty(t, subjects)
		})
	}

	t.Run("expired", func(t *testing.T) {
		a.now = func() time.Time { return time.Now().Add(ssoLoginTTL + time.Second) }
		w, subjects := finish(t, a, login, code, cookie)
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "expired")
		assert.Empty(t, subjects)
	})
	assert.Zero(t, idp.redeemed())
}

func TestStartLogin_SetsAHardenedCookiePerLogin(t *testing.T) {
	a := mustOIDC(t, "https://idp.example.com")
	login := startTestLogin(t, a, "")

	require.Len(t, login.cookies, 1)
	c := login.cookies[0]
	assert.Equal(t, ssoStateCookieName(login.state), c.Name)
	assert.True(t, strings.HasPrefix(c.Name, "sso_state_"))
	assert.True(t, c.HttpOnly)
	assert.Equal(t, http.SameSiteLaxMode, c.SameSite)
	assert.Equal(t, 600, c.MaxAge)
	assert.Equal(t, "/", c.Path)
	assert.False(t, c.Secure, "plain http without a secure verdict")
	assert.NotContains(t, c.Value, login.state, "the cookie does not repeat the public state")
	assert.NotContains(t, login.url, loginSecret(t, a, login), "the secret never leaves the cookie")

	secure := httptest.NewRequest(http.MethodGet, "/api/v1/auth/sso/login", nil)
	secure = secure.WithContext(ContextWithSecureTransport(secure.Context(), true))
	rec := httptest.NewRecorder()
	_, err := a.StartLogin(rec, secure, "")
	require.NoError(t, err)
	assert.True(t, rec.Result().Cookies()[0].Secure)
}

func TestStartLogin_TwoTabsBothComplete(t *testing.T) {
	idp := newStrictIdP(t)
	a := idp.authFor(t)
	jar := browserJar{}

	tab1 := startTestLoginWith(t, a, "/one", jar.list()...)
	jar.apply(tab1.cookies)
	tab2 := startTestLoginWith(t, a, "/two", jar.list()...)
	jar.apply(tab2.cookies)
	require.Len(t, jar, 2, "each login keeps its own cookie")

	// The second tab finishes first, then the first.
	w2, s2 := finish(t, a, tab2, idp.authorize(t, tab2, "user-2"), jar.list()...)
	require.Equal(t, http.StatusFound, w2.Code)
	jar.apply(w2.Result().Cookies())
	w1, s1 := finish(t, a, tab1, idp.authorize(t, tab1, "user-1"), jar.list()...)
	require.Equal(t, http.StatusFound, w1.Code)

	assert.Equal(t, []string{"user-2"}, s2)
	assert.Equal(t, []string{"user-1"}, s1)
	assert.Equal(t, "/two#sso_code=exchange-code-for-user-2", w2.Header().Get("Location"))
	assert.Equal(t, "/one#sso_code=exchange-code-for-user-1", w1.Header().Get("Location"))
}

func TestStartLogin_KeepsAtMostAFewPendingLoginsAndTheOldestFailsCleanly(t *testing.T) {
	idp := newStrictIdP(t)
	a := idp.authFor(t)
	clock := time.Now()
	a.now = func() time.Time { return clock }
	jar := browserJar{}

	var logins []testLogin
	for i := 0; i < maxPendingSSOLogins+1; i++ {
		clock = clock.Add(time.Second)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/sso/login", nil)
		for _, c := range jar.list() {
			req.AddCookie(c)
		}
		rec := httptest.NewRecorder()
		loginURL, err := a.StartLogin(rec, req, "")
		require.NoError(t, err)
		q := mustParseQuery(t, loginURL)
		l := testLogin{url: loginURL, state: q.Get("state"), nonce: q.Get("nonce"), challenge: q.Get("code_challenge"), cookies: rec.Result().Cookies()}
		jar.apply(l.cookies)
		logins = append(logins, l)
	}
	assert.Len(t, jar, maxPendingSSOLogins, "the oldest cookie was deleted when the newest was set")

	oldest := logins[0]
	w, subjects := finish(t, a, oldest, idp.authorize(t, oldest, "user-0"), jar.list()...)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "start sign-in again", "the evicted tab is told what to do")
	assert.Empty(t, subjects)

	for _, l := range logins[1:] {
		w, subjects := finish(t, a, l, idp.authorize(t, l, "user-"+l.state[:4]), jar.list()...)
		assert.Equal(t, http.StatusFound, w.Code, "login %s", l.state[:4])
		assert.Len(t, subjects, 1)
	}
}

func TestStartLogin_RetiresExpiredAndUnreadableCookies(t *testing.T) {
	a := mustOIDC(t, "https://idp.example.com")
	first := startTestLogin(t, a, "")
	a.now = func() time.Time { return time.Now().Add(ssoLoginTTL + time.Minute) }
	junk := &http.Cookie{Name: ssoStateCookiePrefix + "junk", Value: "not-a-cookie"}
	other := &http.Cookie{Name: "session", Value: "keep"}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/sso/login", nil)
	req.AddCookie(first.cookies[0])
	req.AddCookie(junk)
	req.AddCookie(other)
	rec := httptest.NewRecorder()
	_, err := a.StartLogin(rec, req, "")
	require.NoError(t, err)

	deleted := map[string]bool{}
	for _, c := range rec.Result().Cookies() {
		if c.MaxAge < 0 {
			deleted[c.Name] = true
		}
	}
	assert.True(t, deleted[first.cookies[0].Name], "an expired login cookie is deleted")
	assert.True(t, deleted[junk.Name], "an unreadable one is deleted")
	assert.False(t, deleted["session"], "other cookies are left alone")
}

func TestStartLogin_AnotherReplicaWithTheSameKeyCanFinishTheLogin(t *testing.T) {
	idp := newStrictIdP(t)
	key := DeriveSSOStateKey("shared-jwt-secret")
	replicaA := idp.authFor(t, func(c *OIDCConfig) { c.StateKey = key })
	replicaB := idp.authFor(t, func(c *OIDCConfig) { c.StateKey = key })
	stranger := idp.authFor(t, func(c *OIDCConfig) { c.StateKey = DeriveSSOStateKey("another-secret") })
	login := startTestLogin(t, replicaA, "")
	code := idp.authorize(t, login, "user-1")

	refused, _ := finish(t, stranger, login, code, login.cookies...)
	assert.Equal(t, http.StatusBadRequest, refused.Code, "a different key does not verify the cookie")

	w, subjects := finish(t, replicaB, login, code, login.cookies...)
	require.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, []string{"user-1"}, subjects)
}

func TestNewOIDCAuthenticator_RejectsAShortStateKey(t *testing.T) {
	_, err := NewOIDCAuthenticator(OIDCConfig{
		ClientID: "c", IssuerURL: "https://idp.example.com", RedirectURI: "http://localhost/cb", StateKey: []byte("short"),
	}, nil)

	assert.ErrorContains(t, err, "state key")
}

func TestDeriveSSOStateKey_IsStableAndSecretDependent(t *testing.T) {
	assert.Equal(t, DeriveSSOStateKey("s"), DeriveSSOStateKey("s"))
	assert.NotEqual(t, DeriveSSOStateKey("s"), DeriveSSOStateKey("t"))
	assert.GreaterOrEqual(t, len(DeriveSSOStateKey("s")), ssoStateKeyMinBytes)
	assert.NotContains(t, string(DeriveSSOStateKey("hunter2")), "hunter2")
}
