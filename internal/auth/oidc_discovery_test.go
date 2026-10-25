package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// serveTestDiscovery answers the discovery request of a fake provider whose
// issuer is base, pointing at the /oauth/authorize, /oauth/token, /userinfo
// and /.well-known/jwks.json paths the older fakes serve. It reports whether
// it handled the request.
func serveTestDiscovery(w http.ResponseWriter, r *http.Request, base string) bool {
	if r.URL.Path != discoveryPath {
		return false
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"issuer":                 base,
		"authorization_endpoint": base + "/oauth/authorize",
		"token_endpoint":         base + "/oauth/token",
		"userinfo_endpoint":      base + "/userinfo",
		"jwks_uri":               base + "/.well-known/jwks.json",
	})
	return true
}

// keycloakIdP is a fake provider laid out like a Keycloak realm: the issuer is
// <host>/realms/acme/ (with the trailing slash some providers advertise) and
// every endpoint lives under /realms/acme/protocol/openid-connect/, so only
// the discovery document can tell a client where they are.
type keycloakIdP struct {
	t   *testing.T
	srv *httptest.Server

	mu sync.Mutex
	// doc overrides discovery document fields; discoveryStatus, when set,
	// is returned instead of the document.
	doc             map[string]string
	discoveryStatus int
	discoveryHits   int
	// tokenIss is the iss claim of issued id_tokens; empty means the issuer.
	tokenIss  string
	nonce     string
	tokenHits int
}

const keycloakRealm = "/realms/acme"

func newKeycloakIdP(t *testing.T) *keycloakIdP {
	t.Helper()
	key := newOIDCTestKey(t)
	p := &keycloakIdP{t: t, doc: map[string]string{}}
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		p.mu.Lock()
		defer p.mu.Unlock()
		oidcBase := p.srv.URL + keycloakRealm + "/protocol/openid-connect"
		switch r.URL.Path {
		case keycloakRealm + discoveryPath:
			p.discoveryHits++
			if p.discoveryStatus != 0 {
				w.WriteHeader(p.discoveryStatus)
				return
			}
			doc := map[string]string{
				"issuer":                 p.issuer(),
				"authorization_endpoint": oidcBase + "/auth",
				"token_endpoint":         oidcBase + "/token",
				"userinfo_endpoint":      oidcBase + "/userinfo",
				"jwks_uri":               oidcBase + "/certs",
			}
			for k, v := range p.doc {
				doc[k] = v
			}
			_ = json.NewEncoder(w).Encode(doc)
		case keycloakRealm + "/protocol/openid-connect/token":
			p.tokenHits++
			iss := p.tokenIss
			if iss == "" {
				iss = p.issuer()
			}
			idt := signOIDCIDToken(t, key, iss, "test-client", "kc-user-1", "kc@example.com", p.nonce,
				map[string]any{"email_verified": true})
			_, _ = fmt.Fprintf(w, `{"access_token":"kc-access","token_type":"Bearer","id_token":%q}`, idt)
		case keycloakRealm + "/protocol/openid-connect/userinfo":
			_, _ = fmt.Fprint(w, `{"sub":"kc-user-1","email":"kc@example.com","email_verified":true}`)
		case keycloakRealm + "/protocol/openid-connect/certs":
			_, _ = fmt.Fprint(w, jwksBody(t, &key.PublicKey))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(p.srv.Close)
	return p
}

// issuer is the realm issuer, trailing slash included.
func (p *keycloakIdP) issuer() string { return p.srv.URL + keycloakRealm + "/" }

func (p *keycloakIdP) set(f func(p *keycloakIdP)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	f(p)
}

func (p *keycloakIdP) hits() (discovery, token int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.discoveryHits, p.tokenHits
}

func (p *keycloakIdP) auth(t *testing.T) *OIDCAuthenticator {
	t.Helper()
	a, err := NewOIDCAuthenticator(OIDCConfig{
		ClientID: "test-client", ClientSecret: "secret", IssuerURL: p.issuer(),
		RedirectURI: "http://localhost:8080/api/v1/auth/sso/callback",
	}, nil)
	require.NoError(t, err)
	return a
}

func (p *keycloakIdP) completeLogin(t *testing.T, a *OIDCAuthenticator) (*httptest.ResponseRecorder, SSOClaims) {
	t.Helper()
	login := startTestLogin(t, a, "")
	p.set(func(p *keycloakIdP) { p.nonce = login.nonce })
	return callbackClaims(t, a, login)
}

func TestDiscovery_KeycloakRealmWithTrailingSlashIssuerSignsIn(t *testing.T) {
	idp := newKeycloakIdP(t)
	a := idp.auth(t)

	login := startTestLogin(t, a, "")
	authorize, err := url.Parse(login.url)
	require.NoError(t, err)
	assert.Equal(t, idp.srv.URL+keycloakRealm+"/protocol/openid-connect/auth", authorize.Scheme+"://"+authorize.Host+authorize.Path,
		"the login goes to the discovered authorization endpoint")

	idp.set(func(p *keycloakIdP) { p.nonce = login.nonce })
	w, claims := callbackClaims(t, a, login)

	require.Equal(t, http.StatusFound, w.Code, w.Body.String())
	assert.Equal(t, "kc-user-1", claims.Subject)
	assert.True(t, claims.EmailVerified)
	assert.Equal(t, strings.TrimSuffix(idp.issuer(), "/"), claims.Issuer,
		"the stored identity key keeps its slash-free form")
	discovery, token := idp.hits()
	assert.Equal(t, 1, discovery, "metadata is fetched once and cached")
	assert.Equal(t, 1, token)
}

func TestDiscovery_IDTokenIssuerMustMatchExactly(t *testing.T) {
	idp := newKeycloakIdP(t)
	idp.set(func(p *keycloakIdP) { p.tokenIss = strings.TrimSuffix(p.issuer(), "/") })
	a := idp.auth(t)

	w, claims := idp.completeLogin(t, a)

	assert.Equal(t, http.StatusInternalServerError, w.Code, "an iss without the issuer's trailing slash is another issuer")
	assert.Empty(t, claims.Subject)
}

func TestDiscovery_DocumentIssuerMismatchRefusesLoginWithoutRetry(t *testing.T) {
	idp := newKeycloakIdP(t)
	idp.set(func(p *keycloakIdP) { p.doc["issuer"] = strings.TrimSuffix(p.issuer(), "/") })
	a := idp.auth(t)

	rec := httptest.NewRecorder()
	_, err := a.StartLogin(rec, httptest.NewRequest(http.MethodGet, "/api/v1/auth/sso/login", nil), "")

	require.ErrorIs(t, err, ErrSSOProviderUnavailable)
	assert.ErrorContains(t, err, "does not match SSO_ISSUER_URL")
	assert.Empty(t, rec.Result().Cookies(), "a login that cannot start leaves no cookie")
	discovery, _ := idp.hits()
	assert.Equal(t, 1, discovery, "a wrong document is not fetched again within one attempt")
}

func TestDiscovery_RefusesInsecureOrMissingEndpoints(t *testing.T) {
	for name, override := range map[string]map[string]string{
		"plain http token endpoint": {"token_endpoint": "http://idp.example.com/token"},
		"relative jwks uri":         {"jwks_uri": "/certs"},
		"no authorization endpoint": {"authorization_endpoint": ""},
		"no token endpoint":         {"token_endpoint": ""},
		"no jwks uri":               {"jwks_uri": ""},
		"plain http userinfo":       {"userinfo_endpoint": "http://idp.example.com/userinfo"},
	} {
		t.Run(name, func(t *testing.T) {
			idp := newKeycloakIdP(t)
			idp.set(func(p *keycloakIdP) {
				for k, v := range override {
					p.doc[k] = v
				}
			})
			_, err := idp.auth(t).provider(context.Background())
			require.ErrorIs(t, err, ErrSSOProviderUnavailable)
		})
	}
}

func TestDiscovery_RetriesABrieflyUnavailableProvider(t *testing.T) {
	idp := newKeycloakIdP(t)
	idp.set(func(p *keycloakIdP) { p.discoveryStatus = http.StatusServiceUnavailable })
	a := idp.auth(t)
	go func() {
		time.Sleep(discoveryRetryDelay / 2)
		idp.set(func(p *keycloakIdP) { p.discoveryStatus = 0 })
	}()

	meta, err := a.provider(context.Background())

	require.NoError(t, err)
	assert.Equal(t, idp.issuer(), meta.Issuer)
	discovery, _ := idp.hits()
	assert.Equal(t, 2, discovery)
}

func TestDiscovery_DownProviderFailsTheLoginAndTheNextLoginTriesAgain(t *testing.T) {
	idp := newKeycloakIdP(t)
	idp.set(func(p *keycloakIdP) { p.discoveryStatus = http.StatusBadGateway })
	a := idp.auth(t)

	_, err := a.provider(context.Background())
	require.ErrorIs(t, err, ErrSSOProviderUnavailable)
	discovery, _ := idp.hits()
	assert.Equal(t, discoveryAttempts, discovery, "retries are bounded")

	idp.set(func(p *keycloakIdP) { p.discoveryStatus = 0 })
	w, claims := idp.completeLogin(t, a)
	require.Equal(t, http.StatusFound, w.Code, w.Body.String())
	assert.Equal(t, "kc-user-1", claims.Subject, "a failure is not cached")
}

func TestDiscovery_StaleMetadataSurvivesAFailedRefresh(t *testing.T) {
	idp := newKeycloakIdP(t)
	a := idp.auth(t)
	first, err := a.provider(context.Background())
	require.NoError(t, err)

	a.mu.Lock()
	a.metaExpiry = time.Now().Add(-time.Minute)
	a.mu.Unlock()
	idp.set(func(p *keycloakIdP) { p.discoveryStatus = http.StatusInternalServerError })

	again, err := a.provider(context.Background())
	require.NoError(t, err)
	assert.Equal(t, first, again)
}

func TestDiscovery_KeepsTheQueryOfTheAuthorizationEndpoint(t *testing.T) {
	idp := newKeycloakIdP(t)
	idp.set(func(p *keycloakIdP) {
		p.doc["authorization_endpoint"] = p.srv.URL + keycloakRealm + "/protocol/openid-connect/auth?kc_idp_hint=corp"
	})

	login := startTestLogin(t, idp.auth(t), "")

	q := mustParseQuery(t, login.url)
	assert.Equal(t, "corp", q.Get("kc_idp_hint"))
	assert.Equal(t, "test-client", q.Get("client_id"))
	assert.Equal(t, "S256", q.Get("code_challenge_method"))
}

func TestDiscovery_URLDropsOneTrailingSlashOfTheIssuer(t *testing.T) {
	assert.Equal(t, "https://kc.example.com/realms/acme/.well-known/openid-configuration", discoveryURL("https://kc.example.com/realms/acme/"))
	assert.Equal(t, "https://kc.example.com/realms/acme/.well-known/openid-configuration", discoveryURL("https://kc.example.com/realms/acme"))
	assert.Equal(t, "https://accounts.google.com/.well-known/openid-configuration", discoveryURL("https://accounts.google.com"))
}
