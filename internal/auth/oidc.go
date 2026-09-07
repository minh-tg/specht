package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/sync/singleflight"
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
	// jwksFlight coalesces concurrent JWKS refreshes: when a key rotation
	// invalidates the cache, the first callback that misses re-fetches the
	// JWKS while the rest share that single in-flight fetch instead of each
	// stampeding the provider.
	jwksFlight singleflight.Group
}

// ValidateIssuerURL reports whether the configured issuer is acceptable for
// OAuth2/OIDC use. client_secret and access tokens are posted to endpoints
// derived from it, so it must be HTTPS unless it is a loopback address
// (development/testing against localhost issuers over plain HTTP). A missing
// scheme or an http:// issuer pointing off-loopback is rejected.
func ValidateIssuerURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("issuer URL %q is not parseable: %w", raw, err)
	}
	if u.Scheme != "https" {
		host := u.Hostname()
		if u.Scheme != "http" || host == "" || !isLoopbackHost(host) {
			return fmt.Errorf("issuer URL %q must use https", raw)
		}
	}
	return nil
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// NewOIDCAuthenticator builds an SSO authenticator from the given config.
// The issuer URL is validated up front: it is the base for the token,
// userinfo, and JWKS endpoints, and the token exchange posts the client
// secret to it, so a non-HTTPS (off-loopback) issuer is refused rather than
// silently shipping the secret in the clear. An error is returned on invalid
// issuers, so startup wiring can fail fast before serving.
func NewOIDCAuthenticator(cfg OIDCConfig, logger func(msg string, args ...any)) (*OIDCAuthenticator, error) {
	if err := ValidateIssuerURL(cfg.IssuerURL); err != nil {
		return nil, err
	}
	return &OIDCAuthenticator{
		cfg:     cfg,
		logger:  logger,
		jwksURL: strings.TrimSuffix(cfg.IssuerURL, "/") + "/.well-known/jwks.json",
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
		keyCache: make(map[string]any),
	}, nil
}

// Authenticate reports that OIDC credentials are not applicable to the
// bearer-auth chain. Authorization codes flow only through the SSO callback
// (CallbackHandler), never as bearer credentials: accepting "oidc:<code>"
// here would put a one-time code into Authorization headers and logs.
func (a *OIDCAuthenticator) Authenticate(ctx context.Context, token string) (*Identity, error) {
	return nil, ErrNotApplicable
}

func (a *OIDCAuthenticator) exchangeCode(ctx context.Context, code string) (map[string]any, error) {
	// The client secret is POSTed below to an endpoint derived from the
	// issuer; refuse anything but the validated HTTPS (or loopback) issuer
	// base. This is a second line of defense behind the constructor check —
	// a config bug must never send the secret to a plaintext endpoint.
	if err := ValidateIssuerURL(a.cfg.IssuerURL); err != nil {
		return nil, err
	}
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
// JWKS and verifies the issuer, audience, expiry, and (when one was issued)
// nonce claims before accepting it. The OIDC subject (sub) claim is used as
// the stable user identifier.
func (a *OIDCAuthenticator) identityFromIDToken(ctx context.Context, idToken string, wantNonce string) (*Identity, error) {
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

	if wantNonce != "" {
		gotNonce, _ := claims["nonce"].(string)
		if gotNonce == "" || !secureCompare(gotNonce, wantNonce) {
			return nil, ErrInvalidCredential
		}
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

// identityFromUserInfo fetches claims from the issuer's userinfo endpoint
// with the access token and builds the identity from them. When the token
// response also carried an id_token, that token is validated and its sub must
// match the userinfo sub — the userinfo endpoint is not itself
// authenticated beyond the bearer access token, so binding its answer to the
// verified id_token prevents an endpoint compromise (or confused-deputy
// response) from minting an identity for a different subject.
func (a *OIDCAuthenticator) identityFromUserInfo(ctx context.Context, tokenResp map[string]any, wantNonce string) (*Identity, error) {
	accessToken, _ := tokenResp["access_token"].(string)
	if accessToken == "" {
		return nil, ErrInvalidCredential
	}

	idToken, _ := tokenResp["id_token"].(string)
	if idToken != "" {
		// id_token is optional here (some providers only hand it over when
		// openid scope is requested), but when present it must be valid and
		// carry the nonce we issued.
		if _, err := a.identityFromIDToken(ctx, idToken, wantNonce); err != nil {
			return nil, err
		}
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

	if idToken != "" {
		// Cross-check: the userinfo response must describe the same subject
		// as the verified id_token. The id_token's sub is authoritative (it
		// was signature-validated above); userinfo must agree with it.
		idSub, err := idTokenSubject(idToken)
		if err != nil {
			return nil, err
		}
		if idSub == "" || !secureCompare(idSub, info.Sub) {
			return nil, ErrInvalidCredential
		}
	}

	return &Identity{
		UserID: info.Sub,
		Email:  info.Email,
	}, nil
}

// idTokenSubject returns the sub claim of an id_token without validating the
// signature. Callers must have validated the token (identityFromIDToken)
// before trusting the result; this only decodes the payload to compare
// subjects.
func idTokenSubject(idToken string) (string, error) {
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	claims := jwt.MapClaims{}
	if _, _, err := parser.ParseUnverified(idToken, claims); err != nil {
		return "", fmt.Errorf("decode id_token sub: %w", err)
	}
	sub, _ := claims.GetSubject()
	return sub, nil
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

		// The server-issued nonce rides inside the state cookie (see
		// GenerateStateToken), so an id_token is only accepted when its nonce
		// claim matches what this login flow actually sent to the provider.
		_, wantNonce := splitStateNonce(stateCookie.Value)

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
		idToken, _ := tokenResp["id_token"].(string)
		accessToken, _ := tokenResp["access_token"].(string)
		switch {
		case idToken != "" && accessToken != "":
			// Standard OIDC code flow: validate the id_token (signature, iss,
			// aud, exp, nonce) and bind the userinfo response to it by
			// requiring the same sub before trusting userinfo claims.
			ident, err = a.identityFromUserInfo(r.Context(), tokenResp, wantNonce)
		case idToken != "":
			ident, err = a.identityFromIDToken(r.Context(), idToken, wantNonce)
		default:
			// No id_token: the access token authorizes the userinfo fetch
			// directly; there is no signed subject to cross-check against.
			ident, err = a.identityFromUserInfo(r.Context(), tokenResp, wantNonce)
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
// state must come from GenerateStateToken: its nonce half is forwarded as the
// OIDC nonce parameter so the provider echoes it back inside the id_token,
// where the callback binds it to the state cookie.
func (a *OIDCAuthenticator) LoginURL(state string) string {
	_, nonce := splitStateNonce(state)
	params := url.Values{}
	params.Set("client_id", a.cfg.ClientID)
	params.Set("redirect_uri", a.cfg.RedirectURI)
	params.Set("response_type", "code")
	params.Set("scope", "openid email profile")
	params.Set("state", state)
	if nonce != "" {
		params.Set("nonce", nonce)
	}
	return strings.TrimSuffix(a.cfg.IssuerURL, "/") + "/oauth/authorize?" + params.Encode()
}

// GenerateStateToken returns a cryptographically random state value for OAuth2
// CSRF protection. The returned value is "<csrf>.<nonce>": both halves are
// random, the csrf half is echoed back in the provider's state parameter (and
// bound to the sso_state cookie by the router), and the nonce half is sent as
// the OIDC nonce parameter (see LoginURL) and later checked against the
// id_token's nonce claim in the callback. Keeping both in one cookie value
// means the callback can recover the nonce from the very cookie it already
// validated for CSRF, with no extra server-side session state.
func GenerateStateToken() (string, error) {
	csrf, err := randomToken()
	if err != nil {
		return "", fmt.Errorf("generate state token: %w", err)
	}
	nonce, err := randomToken()
	if err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}
	return csrf + "." + nonce, nil
}

func randomToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// splitStateNonce splits a GenerateStateToken value into its csrf and nonce
// halves. Values without a separator (e.g. hand-rolled states in tests, or a
// provider echoing a legacy state) yield an empty nonce; the callback then
// accepts id_tokens without a nonce claim rather than breaking old flows.
func splitStateNonce(state string) (csrf, nonce string) {
	if i := strings.IndexByte(state, '.'); i >= 0 {
		return state[:i], state[i+1:]
	}
	return state, ""
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
// Concurrent misses are coalesced by jwksFlight so a key rotation triggers
// exactly one JWKS fetch; the rest wait on it rather than stampeding the
// issuer.
func (a *OIDCAuthenticator) fetchJWKKey(ctx context.Context, kid string) (any, error) {
	a.mu.RLock()
	key, ok := a.keyCache[kid]
	fresh := ok && time.Now().Before(a.keyExpiry)
	a.mu.RUnlock()
	if fresh {
		return key, nil
	}

	if _, err, _ := a.jwksFlight.Do("refresh", func() (any, error) {
		return nil, a.fetchJWKS(ctx)
	}); err != nil {
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
