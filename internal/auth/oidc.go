package auth

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/minh-tg/specht/internal/netutil"
	"golang.org/x/sync/singleflight"
)

// OIDCConfig configures the OIDC SSO authenticator.
type OIDCConfig struct {
	ClientID     string
	ClientSecret string
	IssuerURL    string // e.g. "https://accounts.google.com"
	RedirectURI  string // OAuth2 callback URL registered with the provider
	// GroupsClaim names the claim carrying IdP group membership for
	// enterprise role mapping. Empty means "groups".
	GroupsClaim string
	// AllowUserInfoOnly permits userinfo-based identity only when the token
	// response omits id_token. This is an insecure compatibility downgrade.
	AllowUserInfoOnly bool
	// StateKey signs the per-login state cookie (see StartLogin). Replicas of
	// one deployment must share it, so main derives it from the JWT secret.
	// Empty means a random key for this process, which suits a single
	// instance and tests; it must be at least 16 bytes otherwise.
	StateKey []byte
}

// jwksCacheTTL bounds how long a fetched JWKS key set is reused before a
// refresh is attempted.
const (
	jwksCacheTTL     = 15 * time.Minute
	maxJWKSBodyBytes = 1 << 20
	// maxTokenResponseBytes bounds the token endpoint reply; a real one is a
	// few kilobytes of JSON.
	maxTokenResponseBytes = 1 << 20
	maxJWKSKeys           = 100
	maxJWKSFieldBytes     = 16 << 10
	maxJWKSKeyIDBytes     = 256
)

type OIDCAuthenticator struct {
	cfg    OIDCConfig
	logger func(msg string, args ...any)

	// stateKey signs the login cookie and seeds the PKCE verifier and nonce.
	stateKey []byte
	// now is the clock for the login cookie's expiry; tests replace it.
	now func() time.Time

	httpClient *http.Client
	mu         sync.RWMutex
	keyCache   map[string]any
	keyExpiry  time.Time
	// meta holds the endpoints from the discovery document once metaOK is
	// set; metaExpiry is when a refresh is next attempted (see provider).
	meta            providerMetadata
	metaOK          bool
	metaExpiry      time.Time
	discoveryFlight singleflight.Group
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
	return netutil.IsLoopbackHost(host)
}

func safeDialContext(dialer *net.Dialer, allowLoopback bool) func(context.Context, string, string) (net.Conn, error) {
	return netutil.SafeDialContext(dialer, allowLoopback)
}

func isBlockedIP(ip net.IP) bool {
	return netutil.IsBlockedIP(ip)
}

// NewOIDCAuthenticator builds an SSO authenticator from the given config.
// The issuer URL is validated up front: the discovery document is fetched
// from it, and the token exchange posts the client secret to an endpoint it
// names, so a non-HTTPS (off-loopback) issuer is refused rather than
// silently shipping the secret in the clear. An error is returned on invalid
// issuers, so startup wiring can fail fast before serving. The provider
// itself is not contacted here; discovery runs on the first login.
func NewOIDCAuthenticator(cfg OIDCConfig, logger func(msg string, args ...any)) (*OIDCAuthenticator, error) {
	if err := ValidateIssuerURL(cfg.IssuerURL); err != nil {
		return nil, err
	}
	stateKey := cfg.StateKey
	if len(stateKey) == 0 {
		stateKey = make([]byte, 32)
		if _, err := rand.Read(stateKey); err != nil {
			return nil, fmt.Errorf("generate sso state key: %w", err)
		}
	} else if len(stateKey) < ssoStateKeyMinBytes {
		return nil, fmt.Errorf("sso state key must be at least %d bytes", ssoStateKeyMinBytes)
	}
	issuer, _ := url.Parse(cfg.IssuerURL)
	allowLoopback := issuer.Scheme == "http" && isLoopbackHost(issuer.Hostname())
	transport := &http.Transport{
		DialContext: safeDialContext(&net.Dialer{Timeout: 10 * time.Second}, allowLoopback),
	}
	return &OIDCAuthenticator{
		cfg:      cfg,
		logger:   logger,
		stateKey: stateKey,
		now:      time.Now,
		httpClient: &http.Client{
			Timeout:   15 * time.Second,
			Transport: transport,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return fmt.Errorf("oidc: redirects are not allowed")
			},
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

func (a *OIDCAuthenticator) exchangeCode(ctx context.Context, code, codeVerifier string) (map[string]any, error) {
	meta, err := a.provider(ctx)
	if err != nil {
		return nil, err
	}
	// The client secret is POSTed below to the discovered token endpoint.
	// Discovery already checked that it is HTTPS (or loopback); checking
	// again here means no later change can send the secret in the clear.
	tokenURL := meta.TokenEndpoint
	if err := validateEndpointURL(tokenURL); err != nil {
		return nil, err
	}
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("client_id", a.cfg.ClientID)
	if a.cfg.ClientSecret != "" {
		// A public client (SSO_PUBLIC_CLIENT) has none; PKCE proves the exchange.
		data.Set("client_secret", a.cfg.ClientSecret)
	}
	data.Set("redirect_uri", a.cfg.RedirectURI)
	if codeVerifier != "" {
		data.Set("code_verifier", codeVerifier)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("token exchange request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token exchange: %w", err)
	}
	// Close errors are best-effort cleanup; HTTP and body-read errors are returned separately.
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange: HTTP %d", resp.StatusCode)
	}

	var tokenResp map[string]any
	if err := netutil.DecodeJSONLimited(resp.Body, maxTokenResponseBytes, &tokenResp); err != nil {
		return nil, fmt.Errorf("decode token response: %w", err)
	}
	return tokenResp, nil
}

// identityFromIDToken validates the id_token signature against the issuer's
// JWKS and verifies the issuer, audience, expiry, and (when one was issued)
// nonce claims before accepting it. The OIDC subject (sub) claim is used as
// the stable user identifier.
func (a *OIDCAuthenticator) identityFromIDToken(ctx context.Context, idToken string, wantNonce string) (*Identity, error) {
	// iss must equal the configured issuer byte for byte, trailing slash
	// included; discovery checked that the provider advertises the same one.
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
	}, jwt.WithValidMethods([]string{"RS256", "ES256"}), jwt.WithIssuer(a.cfg.IssuerURL), jwt.WithAudience(a.cfg.ClientID), jwt.WithExpirationRequired())
	if err != nil {
		return nil, errors.Join(ErrInvalidCredential, err)
	}

	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok || !tok.Valid {
		return nil, ErrInvalidCredential
	}

	// The nonce is always checked: a login flow that did not send one has no
	// way to tell a replayed id_token from a fresh one.
	gotNonce, _ := claims["nonce"].(string)
	if wantNonce == "" || gotNonce == "" || !secureCompare(gotNonce, wantNonce) {
		return nil, ErrInvalidCredential
	}

	sub, _ := claims.GetSubject()
	if sub == "" {
		return nil, ErrInvalidCredential
	}
	email, _ := claims["email"].(string)
	return &Identity{
		UserID:        sub,
		Email:         email,
		EmailVerified: claimIsTrue(claims["email_verified"]),
		Groups:        parseGroupsClaim(claims, a.groupsClaim()),
	}, nil
}

// claimIsTrue reads an OIDC boolean claim. Providers disagree on its type:
// most send a JSON boolean, some send the string "true". Anything else,
// including an absent claim, is false, so a provider that says nothing about
// verification is treated as not having verified.
func claimIsTrue(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return strings.EqualFold(strings.TrimSpace(x), "true")
	default:
		return false
	}
}

// groupsClaim resolves the configured groups claim, defaulting to "groups".
func (a *OIDCAuthenticator) groupsClaim() string {
	if strings.TrimSpace(a.cfg.GroupsClaim) == "" {
		return "groups"
	}
	return a.cfg.GroupsClaim
}

// maxSSOGroups and maxSSOGroupLength bound IdP group intake: groups ride
// into logs and (via provisioning) stored roles, so an unbounded claim
// must not become a bloat vector.
const (
	maxSSOGroups      = 100
	maxSSOGroupLength = 256
)

// parseGroupsClaim extracts IdP group membership from a claims document.
// Providers disagree on shape: a JSON array of strings, a single string,
// or a space-separated string are all accepted. Anything else (numbers,
// objects, nested arrays) is skipped, never coerced — group membership
// gates admin elevation, so ambiguous values must not grant anything.
// appendSSOGroup appends one group name subject to the intake bounds:
// blank and overlong names are dropped, and the list is capped.
func appendSSOGroup(out []string, s string) []string {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > maxSSOGroupLength {
		return out
	}
	if len(out) >= maxSSOGroups {
		return out
	}
	return append(out, s)
}

func parseGroupsClaim(claims map[string]any, claim string) []string {
	raw, ok := claims[claim]
	if !ok || raw == nil {
		return nil
	}
	var out []string
	switch v := raw.(type) {
	case string:
		for _, part := range strings.Fields(v) {
			out = appendSSOGroup(out, part)
		}
	case []string:
		for _, s := range v {
			out = appendSSOGroup(out, s)
		}
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = appendSSOGroup(out, s)
			}
		}
	}
	return out
}

// IsSSOAdmin reports whether IdP group membership elevates a principal to
// admin under the configured admin groups. Matching is exact (IdP group
// names are case-sensitive); empty inputs never match.
func IsSSOAdmin(groups []string, adminGroups []string) bool {
	if len(groups) == 0 || len(adminGroups) == 0 {
		return false
	}
	admin := make(map[string]struct{}, len(adminGroups))
	for _, g := range adminGroups {
		if g != "" {
			admin[g] = struct{}{}
		}
	}
	for _, g := range groups {
		if _, ok := admin[g]; ok {
			return true
		}
	}
	return false
}

// identityFromUserInfo fetches claims from the issuer's userinfo endpoint
// with the access token and builds the identity from them. When the token
// response also carried an id_token, that token is validated and its sub must
// match the userinfo sub — the userinfo endpoint is not itself
// authenticated beyond the bearer access token, so binding its answer to the
// verified id_token prevents an endpoint compromise (or confused-deputy
// response) from minting an identity for a different subject.
// fetchUserInfoBody GETs the issuer's userinfo endpoint with the access
// token and returns the bounded response body.
func (a *OIDCAuthenticator) fetchUserInfoBody(ctx context.Context, accessToken string) ([]byte, error) {
	meta, err := a.provider(ctx)
	if err != nil {
		return nil, err
	}
	userInfoURL := meta.UserinfoEndpoint
	if userInfoURL == "" {
		return nil, errors.New("userinfo: the provider advertises no userinfo_endpoint")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("userinfo: %w", err)
	}
	// Close errors are best-effort cleanup; HTTP and body-read errors are returned separately.
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo: HTTP %d", resp.StatusCode)
	}

	// Bound the userinfo body before decoding twice (typed fields plus the
	// configurable groups claim): providers answer small JSON here, and an
	// unbounded read would turn a compromised endpoint into a memory hog.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("decode userinfo: %w", err)
	}
	return body, nil
}

// mergeSSOGroups merges group membership from the validated id_token (when
// present) and the userinfo body. Either side may omit the claim;
// duplicates collapse.
func mergeSSOGroups(idToken string, body []byte, groupsClaim string) []string {
	seen := make(map[string]struct{})
	var groups []string
	addGroups := func(list []string) {
		for _, g := range list {
			if _, dup := seen[g]; dup {
				continue
			}
			seen[g] = struct{}{}
			groups = append(groups, g)
		}
	}
	if idToken != "" {
		if idGroups, err := idTokenGroups(idToken, groupsClaim); err == nil {
			addGroups(idGroups)
		}
	}
	var rawClaims map[string]any
	if err := json.Unmarshal(body, &rawClaims); err == nil {
		addGroups(parseGroupsClaim(rawClaims, groupsClaim))
	}
	return groups
}

func (a *OIDCAuthenticator) identityFromUserInfo(ctx context.Context, tokenResp map[string]any, wantNonce string) (*Identity, error) {
	accessToken, _ := tokenResp["access_token"].(string)
	if accessToken == "" {
		return nil, ErrInvalidCredential
	}

	rawIDToken, hasIDToken := tokenResp["id_token"]
	idToken, idTokenIsString := rawIDToken.(string)
	if hasIDToken && (!idTokenIsString || idToken == "") {
		return nil, ErrInvalidCredential
	}
	if !hasIDToken && !a.cfg.AllowUserInfoOnly {
		return nil, ErrInvalidCredential
	}
	if idToken != "" {
		// id_token is optional here (some providers only hand it over when
		// openid scope is requested), but when present it must be valid and
		// carry the nonce we issued.
		if _, err := a.identityFromIDToken(ctx, idToken, wantNonce); err != nil {
			return nil, err
		}
	}

	body, err := a.fetchUserInfoBody(ctx, accessToken)
	if err != nil {
		return nil, err
	}
	var info struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified any    `json:"email_verified"`
	}
	if err := json.Unmarshal(body, &info); err != nil {
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

	verified := claimIsTrue(info.EmailVerified)
	if idToken != "" {
		// The signed id_token is the stronger source: if it says the email is
		// not verified, a more permissive userinfo document does not override it.
		if claim, present := idTokenClaim(idToken, "email_verified"); present && !claimIsTrue(claim) {
			verified = false
		}
	}

	return &Identity{
		UserID:        info.Sub,
		Email:         info.Email,
		EmailVerified: verified,
		Groups:        mergeSSOGroups(idToken, body, a.groupsClaim()),
	}, nil
}

// idTokenGroups extracts the groups claim from an already-validated
// id_token. Callers must have validated the token first; this only decodes
// the payload.
func idTokenGroups(idToken, groupsClaim string) ([]string, error) {
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	claims := jwt.MapClaims{}
	if _, _, err := parser.ParseUnverified(idToken, claims); err != nil {
		return nil, fmt.Errorf("decode id_token groups: %w", err)
	}
	return parseGroupsClaim(claims, groupsClaim), nil
}

// idTokenClaim returns one claim of an already-validated id_token and whether
// it was present. Like idTokenGroups it only decodes the payload, so callers
// must have validated the token first.
func idTokenClaim(idToken, name string) (any, bool) {
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	claims := jwt.MapClaims{}
	if _, _, err := parser.ParseUnverified(idToken, claims); err != nil {
		return nil, false
	}
	v, ok := claims[name]
	return v, ok
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

// verifySSOCallbackState checks the callback against the state cookie of the
// login it belongs to. The cookie is named after the state and signed for it,
// so a callback URL replayed from another browser finds no cookie, or one that
// does not verify, and is refused before the code goes anywhere. The cookie
// stays in the browser after a successful callback: redeeming the code it
// issues needs the cookie and clears it (see ExchangeSSOCode). It returns the
// PKCE verifier, the nonce and the browser binding derived from the cookie's
// secret, and the validated return path.
func (a *OIDCAuthenticator) verifySSOCallbackState(w http.ResponseWriter, r *http.Request) (verifier, wantNonce, returnTo, binding string, ok bool) {
	state := r.URL.Query().Get("state")
	if state == "" {
		http.Error(w, "missing state", http.StatusBadRequest)
		return "", "", "", "", false
	}
	name := ssoStateCookieName(state)
	cookie, err := r.Cookie(name)
	if err != nil {
		http.Error(w, "state mismatch: sso login not found or expired, start sign-in again", http.StatusBadRequest)
		return "", "", "", "", false
	}
	login, err := a.openLogin(state, cookie.Value)
	if err != nil {
		msg := "state mismatch"
		if errors.Is(err, errSSOLoginExpired) {
			msg = "state mismatch: sso login expired, start sign-in again"
		}
		http.Error(w, msg, http.StatusBadRequest)
		return "", "", "", "", false
	}

	return a.pkceVerifier(state, login.secret), a.nonce(state, login.secret), login.returnPath, BrowserBinding(login.secret), true
}

// extractCallbackIdentity resolves the callback identity from the token
// response: id_token plus userinfo binding when both are present,
// id_token alone, or userinfo alone.
func (a *OIDCAuthenticator) extractCallbackIdentity(ctx context.Context, tokenResp map[string]any, wantNonce string) (*Identity, error) {
	rawIDToken, hasIDToken := tokenResp["id_token"]
	idToken, idTokenIsString := rawIDToken.(string)
	if hasIDToken && (!idTokenIsString || idToken == "") {
		return nil, ErrInvalidCredential
	}
	accessToken, _ := tokenResp["access_token"].(string)
	switch {
	case idToken != "" && accessToken != "":
		// Standard OIDC code flow: validate the id_token (signature, iss,
		// aud, exp, nonce) and bind the userinfo response to it by
		// requiring the same sub before trusting userinfo claims.
		return a.identityFromUserInfo(ctx, tokenResp, wantNonce)
	case idToken != "":
		return a.identityFromIDToken(ctx, idToken, wantNonce)
	default:
		// No id_token is accepted only for explicitly configured legacy
		// providers; the default requires a verified signed ID token.
		if !hasIDToken && !a.cfg.AllowUserInfoOnly {
			return nil, ErrInvalidCredential
		}
		return a.identityFromUserInfo(ctx, tokenResp, wantNonce)
	}
}

// issueCallbackSession mints the session token for the validated identity
// and delivers it in the redirect URL fragment.
func issueCallbackSession(w http.ResponseWriter, r *http.Request, issuer func(ctx context.Context, claims SSOClaims) (token string, err error), providerIssuer string, ident *Identity, returnTo, binding string) {
	tok, err := issuer(r.Context(), SSOClaims{
		Issuer:         providerIssuer,
		Subject:        ident.UserID,
		Email:          ident.Email,
		EmailVerified:  ident.EmailVerified,
		Groups:         ident.Groups,
		BrowserBinding: binding,
	})
	if err != nil {
		if errors.Is(err, ErrSSONotProvisioned) {
			http.Error(w, "sso account not provisioned", http.StatusForbidden)
			return
		}
		if errors.Is(err, ErrSSOInvalidEmail) {
			http.Error(w, "the identity provider sent an email address this server cannot accept", http.StatusForbidden)
			return
		}
		http.Error(w, "token issuance failed", http.StatusInternalServerError)
		return
	}

	// Deliver the single-use authorization code in the redirect URL fragment
	// (never a query parameter) so it does not leak through Referer headers,
	// browser history, or server access logs. Fragments are not sent to
	// the server, so nothing here ever reads it back; the SPA consumes
	// the code on load and immediately exchanges it for session tokens.
	// The return target is validated as a same-origin path both when it enters
	// the cookie and when it is read back. The code remains in the fragment.
	// nosemgrep: go.lang.security.injection.open-redirect.open-redirect
	http.Redirect(w, r, safeSSOReturnPath(returnTo)+"#sso_code="+url.PathEscape(tok), http.StatusFound)
}

// CallbackHandler returns an http.HandlerFunc that the OAuth2 provider redirects to
// after the user consents. It exchanges the code, extracts identity, and redirects
// back with a single-use exchange code delivered as a URL fragment.
// The issuer callback mints the session token for the validated identity.
// It receives the request context so it can resolve or provision the local
// account, plus the IdP group membership for enterprise role mapping. If it
// returns ErrSSONotProvisioned the callback answers 403 without disclosing
// whether the account exists; ErrSSOInvalidEmail is a 403 that names the
// provider's address as the problem.
func (a *OIDCAuthenticator) CallbackHandler(issuer func(ctx context.Context, claims SSOClaims) (token string, err error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		verifier, wantNonce, returnTo, binding, ok := a.verifySSOCallbackState(w, r)
		if !ok {
			return
		}

		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "missing code", http.StatusBadRequest)
			return
		}

		tokenResp, err := a.exchangeCode(r.Context(), code, verifier)
		if err != nil {
			if a.logger != nil {
				a.logger("oidc token exchange failed", "error", err)
			}
			if errors.Is(err, ErrSSOProviderUnavailable) {
				http.Error(w, "the identity provider is unavailable, try signing in again later", http.StatusServiceUnavailable)
				return
			}
			http.Error(w, "token exchange failed", http.StatusInternalServerError)
			return
		}

		ident, err := a.extractCallbackIdentity(r.Context(), tokenResp, wantNonce)
		if err != nil {
			http.Error(w, "identity extraction failed", http.StatusInternalServerError)
			return
		}

		// The stored identity key keeps the issuer without a trailing slash,
		// as links made before discovery have it. Only this key is trimmed;
		// identityFromIDToken compared the iss claim exactly.
		issueCallbackSession(w, r, issuer, strings.TrimSuffix(a.cfg.IssuerURL, "/"), ident, returnTo, binding)
	}
}

// jwksKey is one JSON Web Key in the issuer's key set.
type jwksKey struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// jwksKeyToPublicKey converts one JWKS entry to a usable public key,
// logging and skipping invalid entries.
func jwksKeyToPublicKey(k jwksKey, logger func(msg string, args ...any)) (any, bool) {
	switch k.Kty {
	case "RSA":
		key, err := parseRSAPublicKey(k.N, k.E)
		if err != nil {
			if logger != nil {
				logger("oidc jwks: skipping invalid RSA key", "kid", k.Kid, "error", err)
			}
			return nil, false
		}
		return key, true
	case "EC":
		key, err := parseECDSAPublicKey(k.Crv, k.X, k.Y)
		if err != nil {
			if logger != nil {
				logger("oidc jwks: skipping invalid EC key", "kid", k.Kid, "error", err)
			}
			return nil, false
		}
		return key, true
	default:
		return nil, false
	}
}

// fetchJWKS downloads the JSON Web Key Set at the discovered jwks_uri and
// caches the keys it contains until jwksCacheTTL elapses.
func (a *OIDCAuthenticator) fetchJWKS(ctx context.Context) error {
	meta, err := a.provider(ctx)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, meta.JWKSURI, nil)
	if err != nil {
		return fmt.Errorf("jwks request: %w", err)
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("jwks: %w", err)
	}
	// Close errors are best-effort cleanup; HTTP and body-read errors are returned separately.
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks: HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBodyBytes+1))
	if err != nil {
		return fmt.Errorf("read jwks: %w", err)
	}
	if len(body) > maxJWKSBodyBytes {
		return fmt.Errorf("jwks: response exceeds %d bytes", maxJWKSBodyBytes)
	}
	var jwks struct {
		Keys []jwksKey `json:"keys"`
	}
	if err := json.Unmarshal(body, &jwks); err != nil {
		return fmt.Errorf("decode jwks: %w", err)
	}
	if len(jwks.Keys) > maxJWKSKeys {
		return fmt.Errorf("jwks: too many keys (maximum %d)", maxJWKSKeys)
	}

	keys := make(map[string]any, len(jwks.Keys))
	for _, k := range jwks.Keys {
		if len(k.Kid) > maxJWKSKeyIDBytes || len(k.N) > maxJWKSFieldBytes || len(k.E) > maxJWKSFieldBytes || len(k.X) > maxJWKSFieldBytes || len(k.Y) > maxJWKSFieldBytes || len(k.Crv) > maxJWKSFieldBytes {
			continue
		}
		if k.Kid == "" {
			continue
		}
		if key, ok := jwksKeyToPublicKey(k, a.logger); ok {
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
