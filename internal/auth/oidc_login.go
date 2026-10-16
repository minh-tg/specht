package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The pending state of one SSO login lives in a cookie of the browser that
// started it, never in anything the authorization URL carries. The cookie
// holds a random per-login secret and the validated return path, and is
// signed with a server key over the state, the secret and the expiry. The
// PKCE verifier and the OIDC nonce are derived from the secret, so someone who
// holds a callback URL (code and state) but not that browser's cookie cannot
// complete the login: they cannot forge a cookie that verifies for the state,
// and the code is useless without the verifier.
//
// Each login gets its own cookie, named after a hash of its state, so two tabs
// can sign in at once. A browser keeps at most maxPendingSSOLogins of them;
// starting another one retires the oldest, and that older login then fails
// with "sso login expired".
const (
	ssoStateCookiePrefix = "sso_state_"
	ssoLoginTTL          = 10 * time.Minute
	maxPendingSSOLogins  = 4
	ssoCookieVersion     = "v1"
	// ssoStateKeyMinBytes is the shortest accepted OIDCConfig.StateKey.
	ssoStateKeyMinBytes = 16
)

// errSSOLoginInvalid reports a state cookie that is missing, malformed,
// signed for another state, or tampered with. errSSOLoginExpired reports a
// well-signed cookie past its expiry.
var (
	errSSOLoginInvalid = errors.New("sso login cookie invalid")
	errSSOLoginExpired = errors.New("sso login cookie expired")
)

// ssoLogin is the pending state of one login, as carried by its cookie.
type ssoLogin struct {
	secret     string
	expires    time.Time
	returnPath string
}

// DeriveSSOStateKey derives the key that signs SSO login cookies from the
// server's JWT secret, so every replica that shares that secret can finish a
// login another one started, without a second secret to configure.
func DeriveSSOStateKey(jwtSecret string) []byte {
	mac := hmac.New(sha256.New, []byte(jwtSecret))
	mac.Write([]byte("specht-sso-state-key-v1"))
	return mac.Sum(nil)
}

// GenerateStateToken returns a random OAuth2 state value (256 bits). It is
// public: it rides in the authorization URL and comes back in the callback.
// Everything that must stay secret is bound to the per-login cookie secret
// instead (see ssoLogin).
func GenerateStateToken() (string, error) {
	state, err := randomToken()
	if err != nil {
		return "", fmt.Errorf("generate state token: %w", err)
	}
	return state, nil
}

func randomToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// secureCompare reports whether a and b are equal in constant time.
func secureCompare(a, b string) bool {
	return hmac.Equal([]byte(a), []byte(b))
}

// ssoStateCookieName names the cookie of the login that uses state.
func ssoStateCookieName(state string) string {
	sum := sha256.Sum256([]byte(state))
	return ssoStateCookiePrefix + base64.RawURLEncoding.EncodeToString(sum[:12])
}

// sign returns the HMAC of the parts under the server key, separated so no two
// different part lists give the same input.
func (a *OIDCAuthenticator) sign(parts ...string) string {
	mac := hmac.New(sha256.New, a.stateKey)
	for _, p := range parts {
		mac.Write([]byte(p))
		mac.Write([]byte{0})
	}
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// pkceVerifier is the RFC 7636 code verifier of one login. It depends on the
// cookie secret, so it cannot be computed from the callback URL. Because it
// comes from the server key and not from the client secret, a public client
// gets PKCE too.
func (a *OIDCAuthenticator) pkceVerifier(state, secret string) string {
	return a.sign("specht-oidc-pkce-v2", secret, state)
}

// nonce is the OIDC nonce of one login. The authorization URL carries it, so
// it is derived one way from the secret and reveals nothing about it.
func (a *OIDCAuthenticator) nonce(state, secret string) string {
	return a.sign("specht-oidc-nonce-v2", secret, state)
}

// pkceChallenge is the S256 transform of a verifier.
func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// sealLogin encodes a pending login as a cookie value:
// v1.<secret>.<expiry unix>.<return path>.<signature>. Every field is
// base64url or digits, so the dot is a safe separator.
func (a *OIDCAuthenticator) sealLogin(state string, l ssoLogin) string {
	body := strings.Join([]string{
		ssoCookieVersion,
		l.secret,
		strconv.FormatInt(l.expires.Unix(), 10),
		base64.RawURLEncoding.EncodeToString([]byte(l.returnPath)),
	}, ".")
	return body + "." + a.sign("specht-sso-login-cookie-v1", state, body)
}

// openLogin checks a cookie value against the state it was issued for and
// returns the pending login. The signature covers the state, so a cookie
// copied from another login (or another browser's own login) does not verify.
func (a *OIDCAuthenticator) openLogin(state, value string) (ssoLogin, error) {
	body, sig, ok := cutLast(value, ".")
	if !ok || !secureCompare(sig, a.sign("specht-sso-login-cookie-v1", state, body)) {
		return ssoLogin{}, errSSOLoginInvalid
	}
	parts := strings.Split(body, ".")
	if len(parts) != 4 || parts[0] != ssoCookieVersion || parts[1] == "" {
		return ssoLogin{}, errSSOLoginInvalid
	}
	unix, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return ssoLogin{}, errSSOLoginInvalid
	}
	path, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		return ssoLogin{}, errSSOLoginInvalid
	}
	l := ssoLogin{secret: parts[1], expires: time.Unix(unix, 0), returnPath: safeSSOReturnPath(string(path))}
	if !a.now().Before(l.expires) {
		return ssoLogin{}, errSSOLoginExpired
	}
	return l, nil
}

func cutLast(s, sep string) (before, after string, found bool) {
	i := strings.LastIndex(s, sep)
	if i < 0 {
		return s, "", false
	}
	return s[:i], s[i+len(sep):], true
}

// ssoCookie builds a state cookie with the attributes every one of them
// shares; maxAge is in seconds and negative deletes it.
func ssoCookie(name, value string, maxAge int, secure bool) *http.Cookie {
	// Secure is the caller's SecureTransport verdict. It is true when TLS ends
	// in this process, or when the direct peer is listed in TRUSTED_PROXIES and
	// sent X-Forwarded-Proto: https. It is false for plain HTTP, and also for
	// HTTPS behind a proxy that is not in TRUSTED_PROXIES (the default is
	// empty): forwarding headers from any other peer are ignored on purpose, so
	// a client cannot set the flag. An operator who terminates TLS at a proxy
	// must list it in TRUSTED_PROXIES to get Secure cookies (deploy/README.md,
	// "Reverse proxy").
	// nosemgrep: go.lang.security.audit.net.cookie-missing-secure.cookie-missing-secure
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   secure,
	}
}

// StartLogin begins an SSO login for the browser behind r. It sets the login's
// state cookie on w and returns the identity provider URL to redirect to.
// returnPath is where the SPA should land afterwards; it is reduced to a
// same-origin path before it is stored. Cookies of this browser's older
// logins are retired so that at most maxPendingSSOLogins stay pending.
func (a *OIDCAuthenticator) StartLogin(w http.ResponseWriter, r *http.Request, returnPath string) (string, error) {
	state, err := GenerateStateToken()
	if err != nil {
		return "", err
	}
	secret, err := randomToken()
	if err != nil {
		return "", fmt.Errorf("generate login secret: %w", err)
	}
	// realIPMiddleware has decided whether this connection is secure,
	// consulting the configured trusted proxies; SecureTransport honors that
	// verdict and never trusts a client-supplied X-Forwarded-Proto on its own.
	secure := SecureTransport(r)
	a.retireOldLogins(w, r, secure)

	login := ssoLogin{
		secret:     secret,
		expires:    a.now().Add(ssoLoginTTL),
		returnPath: safeSSOReturnPath(returnPath),
	}
	// Secure comes from the proxy-aware transport verdict above.
	// nosemgrep: go.lang.security.audit.net.cookie-missing-secure.cookie-missing-secure
	http.SetCookie(w, ssoCookie(ssoStateCookieName(state), a.sealLogin(state, login), int(ssoLoginTTL/time.Second), secure))
	return a.loginURL(state, secret), nil
}

// retireOldLogins deletes this browser's expired or unreadable state cookies
// and, when more than maxPendingSSOLogins-1 are left, the oldest ones, to make
// room for the login being started.
func (a *OIDCAuthenticator) retireOldLogins(w http.ResponseWriter, r *http.Request, secure bool) {
	type pending struct {
		name    string
		expires time.Time
	}
	var live []pending
	for _, c := range r.Cookies() {
		if !strings.HasPrefix(c.Name, ssoStateCookiePrefix) {
			continue
		}
		parts := strings.Split(c.Value, ".")
		unix, err := strconv.ParseInt(partAt(parts, 2), 10, 64)
		if len(parts) != 5 || err != nil || !a.now().Before(time.Unix(unix, 0)) {
			// nosemgrep: go.lang.security.audit.net.cookie-missing-secure.cookie-missing-secure
			http.SetCookie(w, ssoCookie(c.Name, "", -1, secure))
			continue
		}
		live = append(live, pending{c.Name, time.Unix(unix, 0)})
	}
	sort.Slice(live, func(i, j int) bool { return live[i].expires.After(live[j].expires) })
	for i := maxPendingSSOLogins - 1; i < len(live); i++ {
		// nosemgrep: go.lang.security.audit.net.cookie-missing-secure.cookie-missing-secure
		http.SetCookie(w, ssoCookie(live[i].name, "", -1, secure))
	}
}

func partAt(parts []string, i int) string {
	if i < len(parts) {
		return parts[i]
	}
	return ""
}

// loginURL builds the authorization URL of one login. The nonce and the PKCE
// challenge are derived from the cookie secret.
func (a *OIDCAuthenticator) loginURL(state, secret string) string {
	params := url.Values{}
	params.Set("client_id", a.cfg.ClientID)
	params.Set("redirect_uri", a.cfg.RedirectURI)
	params.Set("response_type", "code")
	params.Set("scope", "openid email profile")
	params.Set("state", state)
	params.Set("nonce", a.nonce(state, secret))
	params.Set("code_challenge", pkceChallenge(a.pkceVerifier(state, secret)))
	params.Set("code_challenge_method", "S256")
	return strings.TrimSuffix(a.cfg.IssuerURL, "/") + "/oauth/authorize?" + params.Encode()
}
