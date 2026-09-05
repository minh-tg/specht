package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// OIDCConfig configures the OIDC SSO authenticator.
type OIDCConfig struct {
	ClientID     string
	ClientSecret string
	IssuerURL    string // e.g. "https://accounts.google.com"
	RedirectURI  string // OAuth2 callback URL registered with the provider
}

type OIDCAuthenticator struct {
	cfg    OIDCConfig
	logger func(msg string, args ...any)
}

// NewOIDCAuthenticator builds an SSO authenticator from the given config.
func NewOIDCAuthenticator(cfg OIDCConfig, logger func(msg string, args ...any)) *OIDCAuthenticator {
	return &OIDCAuthenticator{cfg: cfg, logger: logger}
}

// Authenticate exchanges an OAuth2 code (from the redirect callback) for an
// OIDC Identity. The token is expected in the form "oidc:<code>".
func (a *OIDCAuthenticator) Authenticate(ctx context.Context, token string) (*Identity, error) {
	if !strings.HasPrefix(token, "oidc:") {
		return nil, ErrNotApplicable
	}
	code := strings.TrimPrefix(token, "oidc:")

	tokenResp, err := a.exchangeCode(ctx, code)
	if err != nil {
		return nil, ErrInvalidCredential
	}

	idToken, ok := tokenResp["id_token"].(string)
	if !ok || idToken == "" {
		return a.identityFromUserInfo(ctx, tokenResp)
	}

	return a.identityFromIDToken(idToken)
}

func (a *OIDCAuthenticator) exchangeCode(ctx context.Context, code string) (map[string]any, error) {
	tokenURL := strings.TrimSuffix(a.cfg.IssuerURL, "/") + "/oauth/token"
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("client_id", a.cfg.ClientID)
	data.Set("client_secret", a.cfg.ClientSecret)
	data.Set("redirect_uri", a.cfg.RedirectURI)

	resp, err := http.PostForm(tokenURL, data)
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

func (a *OIDCAuthenticator) identityFromIDToken(idToken string) (*Identity, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("malformed id_token")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode id_token payload: %w", err)
	}
	var claims struct {
		Sub   string `json:"sub"`
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return nil, fmt.Errorf("unmarshal id_token claims: %w", err)
	}
	if claims.Sub == "" {
		return nil, ErrInvalidCredential
	}
	return &Identity{
		UserID: claims.Name,
		Email:  claims.Email,
	}, nil
}

func (a *OIDCAuthenticator) identityFromUserInfo(ctx context.Context, tokenResp map[string]any) (*Identity, error) {
	accessToken, _ := tokenResp["access_token"].(string)
	if accessToken == "" {
		return nil, ErrInvalidCredential
	}

	userInfoURL := strings.TrimSuffix(a.cfg.IssuerURL, "/") + "/userinfo"
	req, _ := http.NewRequestWithContext(ctx, "GET", userInfoURL, nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := http.DefaultClient.Do(req)
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
		Name  string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("decode userinfo: %w", err)
	}
	if info.Sub == "" {
		return nil, ErrInvalidCredential
	}
	return &Identity{
		UserID: info.Name,
		Email:  info.Email,
	}, nil
}

// CallbackHandler returns an http.HandlerFunc that the OAuth2 provider redirects to
// after the user consents. It exchanges the code, extracts identity, and redirects
// back with a session token.
func (a *OIDCAuthenticator) CallbackHandler(issuer func(userID, email string) (token string, err error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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
			ident, err = a.identityFromIDToken(idToken)
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

		http.Redirect(w, r, "/?token="+url.QueryEscape(tok), http.StatusFound)
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

// stateHash generates a CSRF state token for the OAuth2 flow.
func stateHash(state string) string {
	sum := sha256.Sum256([]byte(state))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// _ keeps the import used for future use.
var _ = stateHash
