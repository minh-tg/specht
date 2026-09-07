package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// OIDCConfig configures the OIDC SSO authenticator.
type OIDCConfig struct {
	ClientID     string
	ClientSecret string
	IssuerURL    string // e.g. "https://accounts.google.com"
	RedirectURI  string // OAuth2 callback URL registered with the provider
}

// jwksCacheTTL bounds how long a fetched JWKS key set is reused before a
// refresh is attempted.
const jwksCacheTTL = 15 * time.Minute

type OIDCAuthenticator struct {
	cfg    OIDCConfig
	logger func(msg string, args ...any)

	jwksURL    string
	httpClient *http.Client
	mu         sync.RWMutex
	keyCache   map[string]any
	keyExpiry  time.Time
}

// NewOIDCAuthenticator builds an SSO authenticator from the given config.
func NewOIDCAuthenticator(cfg OIDCConfig, logger func(msg string, args ...any)) *OIDCAuthenticator {
	return &OIDCAuthenticator{
		cfg:     cfg,
		logger:  logger,
		jwksURL: strings.TrimSuffix(cfg.IssuerURL, "/") + "/.well-known/jwks.json",
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
		keyCache: make(map[string]any),
	}
}

// Authenticate reports that OIDC credentials are not applicable to the
// bearer-auth chain. Authorization codes flow only through the SSO callback
// (CallbackHandler), never as bearer credentials: accepting "oidc:<code>"
// here would put a one-time code into Authorization headers and logs.
func (a *OIDCAuthenticator) Authenticate(ctx context.Context, token string) (*Identity, error) {
	return nil, ErrNotApplicable
}

func (a *OIDCAuthenticator) exchangeCode(ctx context.Context, code string) (map[string]any, error) {
	tokenURL := strings.TrimSuffix(a.cfg.IssuerURL, "/") + "/oauth/token"
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("client_id", a.cfg.ClientID)
	data.Set("client_secret", a.cfg.ClientSecret)
	data.Set("redirect_uri", a.cfg.RedirectURI)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("token exchange request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token exchange: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange: HTTP %d", resp.StatusCode)
	}

	var tokenResp map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("decode token response: %w", err)
	}
	return tokenResp, nil
}

// identityFromIDToken validates the id_token signature against the issuer's
// JWKS and verifies the issuer, audience, and expiry claims before accepting
// it. The OIDC subject (sub) claim is used as the stable user identifier.
func (a *OIDCAuthenticator) identityFromIDToken(ctx context.Context, idToken string) (*Identity, error) {
	tok, err := jwt.Parse(idToken, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			if _, ok := t.Method.(*jwt.SigningMethodECDSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
		}
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, fmt.Errorf("id_token missing kid")
		}
		return a.fetchJWKKey(ctx, kid)
	}, jwt.WithValidMethods([]string{"RS256", "ES256"}), jwt.WithIssuer(strings.TrimSuffix(a.cfg.IssuerURL, "/")), jwt.WithAudience(a.cfg.ClientID), jwt.WithExpirationRequired())
	if err != nil {
		return nil, errors.Join(ErrInvalidCredential, err)
	}

	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok || !tok.Valid {
		return nil, ErrInvalidCredential
	}

	sub, _ := claims.GetSubject()
	if sub == "" {
		return nil, ErrInvalidCredential
	}
	email, _ := claims["email"].(string)
	return &Identity{
		UserID: sub,
		Email:  email,
	}, nil
}

func (a *OIDCAuthenticator) identityFromUserInfo(ctx context.Context, tokenResp map[string]any) (*Identity, error) {
	accessToken, _ := tokenResp["access_token"].(string)
	if accessToken == "" {
		return nil, ErrInvalidCredential
	}

	userInfoURL := strings.TrimSuffix(a.cfg.IssuerURL, "/") + "/userinfo"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("userinfo: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo: HTTP %d", resp.StatusCode)
	}

	var info struct {
		Sub   string `json:"sub"`
		Email string `json:"email"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("decode userinfo: %w", err)
	}
	if info.Sub == "" {
		return nil, ErrInvalidCredential
	}
	return &Identity{
		UserID: info.Sub,
		Email:  info.Email,
	}, nil
}

// secureCookie marks a cookie Secure when the request arrived over TLS, either
// directly or through a TLS-terminating proxy (matching realIPMiddleware's
// X-Forwarded-* trust).
func secureCookie(r *http.Request, c *http.Cookie) *http.Cookie {
	secure := r.TLS != nil
	if !secure && strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		secure = true
	}
	c.Secure = secure
	return c
}

// CallbackHandler returns an http.HandlerFunc that the OAuth2 provider redirects to
// after the user consents. It exchanges the code, extracts identity, and redirects
// back with a session token delivered as a URL fragment.
func (a *OIDCAuthenticator) CallbackHandler(issuer func(userID, email string) (token string, err error)) http.HandlerFunc {
	const stateCookieName = "sso_state"

	return func(w http.ResponseWriter, r *http.Request) {
		state := r.URL.Query().Get("state")
		if state == "" {
			http.Error(w, "missing state", http.StatusBadRequest)
			return
		}
		stateCookie, err := r.Cookie(stateCookieName)
		if err != nil || !secureCompare(state, stateCookie.Value) {
			http.Error(w, "state mismatch", http.StatusBadRequest)
			return
		}
		// The state value is single-use: clear it before any further work so a
		// replayed callback can never pass this check again.
		http.SetCookie(w, secureCookie(r, &http.Cookie{
			Name:     stateCookieName,
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		}))

		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "missing code", http.StatusBadRequest)
			return
		}

		tokenResp, err := a.exchangeCode(r.Context(), code)
		if err != nil {
			if a.logger != nil {
				a.logger("oidc token exchange failed", "error", err)
			}
			http.Error(w, "token exchange failed", http.StatusInternalServerError)
			return
		}

		var ident *Identity
		if idToken, _ := tokenResp["id_token"].(string); idToken != "" {
			ident, err = a.identityFromIDToken(r.Context(), idToken)
		} else {
			ident, err = a.identityFromUserInfo(r.Context(), tokenResp)
		}
		if err != nil {
			http.Error(w, "identity extraction failed", http.StatusInternalServerError)
			return
		}

		tok, err := issuer(ident.UserID, ident.Email)
		if err != nil {
			http.Error(w, "token issuance failed", http.StatusInternalServerError)
			return
		}

		// Deliver the session token in the redirect URL fragment (never a
		// query parameter) so it does not leak through Referer headers,
		// browser history, or server access logs. Fragments are not sent to
		// the server, so nothing here ever reads it back; the SPA consumes
		// the fragment on load and keeps the token in memory.
		http.Redirect(w, r, "/#sso_token="+url.PathEscape(tok), http.StatusFound)
	}
}

// LoginURL returns the authorization URL the user must visit to start SSO.
func (a *OIDCAuthenticator) LoginURL(state string) string {
	params := url.Values{}
	params.Set("client_id", a.cfg.ClientID)
	params.Set("redirect_uri", a.cfg.RedirectURI)
	params.Set("response_type", "code")
	params.Set("scope", "openid email profile")
	params.Set("state", state)
	return strings.TrimSuffix(a.cfg.IssuerURL, "/") + "/oauth/authorize?" + params.Encode()
}

// GenerateStateToken returns a cryptographically random state value for OAuth2
// CSRF protection.
func GenerateStateToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate state token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// secureCompare reports whether a and b are equal in constant time.
func secureCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// fetchJWKS downloads the issuer's JSON Web Key Set and caches the keys it
// contains until jwksCacheTTL elapses.
func (a *OIDCAuthenticator) fetchJWKS(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.jwksURL, nil)
	if err != nil {
		return fmt.Errorf("jwks request: %w", err)
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("jwks: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks: HTTP %d", resp.StatusCode)
	}

	var jwks struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			Alg string `json:"alg"`
			Use string `json:"use"`
			N   string `json:"n"`
			E   string `json:"e"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Y   string `json:"y"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return fmt.Errorf("decode jwks: %w", err)
	}

	keys := make(map[string]any, len(jwks.Keys))
	for _, k := range jwks.Keys {
		if k.Kid == "" {
			continue
		}
		switch k.Kty {
		case "RSA":
			key, err := parseRSAPublicKey(k.N, k.E)
			if err != nil {
				if a.logger != nil {
					a.logger("oidc jwks: skipping invalid RSA key", "kid", k.Kid, "error", err)
				}
				continue
			}
			keys[k.Kid] = key
		case "EC":
			key, err := parseECDSAPublicKey(k.Crv, k.X, k.Y)
			if err != nil {
				if a.logger != nil {
					a.logger("oidc jwks: skipping invalid EC key", "kid", k.Kid, "error", err)
				}
				continue
			}
			keys[k.Kid] = key
		}
	}
	if len(keys) == 0 {
		return fmt.Errorf("jwks: no usable keys")
	}

	a.mu.Lock()
	a.keyCache = keys
	a.keyExpiry = time.Now().Add(jwksCacheTTL)
	a.mu.Unlock()
	return nil
}

// fetchJWKKey returns the cached public key for kid, refreshing the JWKS when
// the key is unknown or the cache is stale. The double-checked pattern keeps
// cache reads cheap: most callbacks hit the first RLock check, and only a
// stale/missing key triggers a refresh followed by a second cache lookup.
func (a *OIDCAuthenticator) fetchJWKKey(ctx context.Context, kid string) (any, error) {
	a.mu.RLock()
	key, ok := a.keyCache[kid]
	fresh := ok && time.Now().Before(a.keyExpiry)
	a.mu.RUnlock()
	if fresh {
		return key, nil
	}

	if err := a.fetchJWKS(ctx); err != nil {
		return nil, err
	}

	a.mu.RLock()
	defer a.mu.RUnlock()
	key, ok = a.keyCache[kid]
	if !ok {
		return nil, fmt.Errorf("jwks: no key for kid %q", kid)
	}
	return key, nil
}
