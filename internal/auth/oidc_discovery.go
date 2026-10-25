package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/minh-tg/specht/internal/netutil"
)

// ErrSSOProviderUnavailable reports that the provider's discovery document
// could not be fetched or did not validate, so no endpoint is known. The login
// route answers it with 503 instead of redirecting anywhere.
var ErrSSOProviderUnavailable = errors.New("sso identity provider unavailable")

const (
	// discoveryPath is appended to the issuer, after removing one trailing
	// slash, to find the provider metadata (OpenID Connect Discovery 1.0,
	// section 4).
	discoveryPath = "/.well-known/openid-configuration"
	// discoveryCacheTTL is how long fetched metadata is used before a refresh
	// is attempted. A failed refresh keeps the previous metadata.
	discoveryCacheTTL = time.Hour
	// discoveryAttempts and discoveryRetryDelay bound one fetch: an IdP that
	// is briefly down costs a login at most this many tries before it gets a
	// 503, and the next login tries again.
	discoveryAttempts     = 3
	discoveryRetryDelay   = 250 * time.Millisecond
	maxDiscoveryBodyBytes = 1 << 20
)

// providerMetadata holds the endpoints taken from the provider's discovery
// document.
type providerMetadata struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// errDiscoveryInvalid marks a document that was served but is wrong (issuer
// mismatch, missing or insecure endpoint). Fetching it again gives the same
// answer, so it is not retried.
type errDiscoveryInvalid struct{ msg string }

func (e errDiscoveryInvalid) Error() string { return e.msg }

func discoveryURL(issuer string) string {
	return strings.TrimSuffix(issuer, "/") + discoveryPath
}

// provider returns the discovered endpoints. Metadata is fetched on first use,
// not at startup, so an IdP that is down while the server boots does not stop
// it; concurrent callers share one fetch. Fresh metadata is served from the
// cache. When a refresh of stale metadata fails, the stale copy is kept.
func (a *OIDCAuthenticator) provider(ctx context.Context) (providerMetadata, error) {
	a.mu.RLock()
	cached, have := a.meta, a.metaOK
	fresh := have && a.now().Before(a.metaExpiry)
	a.mu.RUnlock()
	if fresh {
		return cached, nil
	}

	v, err, _ := a.discoveryFlight.Do("discover", func() (any, error) {
		return a.discover(ctx)
	})
	if err != nil {
		if have {
			if a.logger != nil {
				a.logger("oidc discovery refresh failed, keeping previous metadata", "error", err)
			}
			return cached, nil
		}
		return providerMetadata{}, fmt.Errorf("%w: %w", ErrSSOProviderUnavailable, err)
	}
	return v.(providerMetadata), nil
}

// discover fetches and validates the discovery document, retrying transport
// and server errors a bounded number of times, and caches the result.
func (a *OIDCAuthenticator) discover(ctx context.Context) (providerMetadata, error) {
	var lastErr error
	for attempt := range discoveryAttempts {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return providerMetadata{}, errors.Join(lastErr, ctx.Err())
			case <-time.After(discoveryRetryDelay):
			}
		}
		meta, err := a.fetchDiscovery(ctx)
		if err == nil {
			a.mu.Lock()
			a.meta, a.metaOK = meta, true
			a.metaExpiry = a.now().Add(discoveryCacheTTL)
			a.mu.Unlock()
			return meta, nil
		}
		lastErr = err
		var invalid errDiscoveryInvalid
		if errors.As(err, &invalid) {
			break
		}
	}
	return providerMetadata{}, lastErr
}

func (a *OIDCAuthenticator) fetchDiscovery(ctx context.Context) (providerMetadata, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL(a.cfg.IssuerURL), nil)
	if err != nil {
		return providerMetadata{}, fmt.Errorf("discovery request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return providerMetadata{}, fmt.Errorf("discovery: %w", err)
	}
	// Close errors are best-effort cleanup; HTTP and body-read errors are returned separately.
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return providerMetadata{}, fmt.Errorf("discovery: %s returned HTTP %d", req.URL, resp.StatusCode)
	}
	var meta providerMetadata
	if err := netutil.DecodeJSONLimited(resp.Body, maxDiscoveryBodyBytes, &meta); err != nil {
		return providerMetadata{}, errDiscoveryInvalid{fmt.Sprintf("decode discovery document: %v", err)}
	}
	if err := a.validateMetadata(meta); err != nil {
		return providerMetadata{}, err
	}
	return meta, nil
}

// validateMetadata applies OpenID Connect Discovery 1.0 section 4.3: the
// advertised issuer must equal the configured one exactly, trailing slash
// included, because ID tokens are checked against it. Every endpoint Specht
// calls must be an absolute https URL (plain http only for a loopback host),
// since the client secret and access tokens are sent to them.
func (a *OIDCAuthenticator) validateMetadata(m providerMetadata) error {
	if m.Issuer != a.cfg.IssuerURL {
		msg := fmt.Sprintf("discovery document issuer %q does not match configured SSO_ISSUER_URL %q: set SSO_ISSUER_URL to exactly the issuer value from %s", m.Issuer, a.cfg.IssuerURL, discoveryURL(a.cfg.IssuerURL))
		if a.logger != nil {
			a.logger("oidc discovery issuer mismatch: " + msg)
		}
		return errDiscoveryInvalid{msg}
	}
	required := []struct{ name, value string }{
		{"authorization_endpoint", m.AuthorizationEndpoint},
		{"token_endpoint", m.TokenEndpoint},
		{"jwks_uri", m.JWKSURI},
	}
	for _, f := range required {
		if f.value == "" {
			return errDiscoveryInvalid{fmt.Sprintf("discovery document has no %s", f.name)}
		}
		if err := validateEndpointURL(f.value); err != nil {
			return errDiscoveryInvalid{fmt.Sprintf("discovery document %s: %v", f.name, err)}
		}
	}
	if m.UserinfoEndpoint != "" {
		if err := validateEndpointURL(m.UserinfoEndpoint); err != nil {
			return errDiscoveryInvalid{fmt.Sprintf("discovery document userinfo_endpoint: %v", err)}
		}
	}
	return nil
}

func validateEndpointURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%q is not a URL: %w", raw, err)
	}
	if u.Host == "" {
		return fmt.Errorf("%q is not an absolute URL", raw)
	}
	if u.Fragment != "" {
		return fmt.Errorf("%q carries a fragment", raw)
	}
	return ValidateIssuerURL(raw)
}
