// Package config centralizes environment parsing and defaults for the
// server, the CVE watcher, and CLI watcher subcommands. A malformed optional
// watcher setting must not fail startup when the watcher is disabled; the
// enabled path validates once through Watcher.Load (or Server.Load when the
// server runs the watcher).
package config

import (
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

// Defaults shared by the server, watcher, and CLI.
const (
	DefaultServerAddr    = ":8080"
	DefaultInventoryTTL  = 2160 * time.Hour // 90d
	DefaultWatcherPoll   = 6 * time.Hour
	DefaultWatcherBatch  = 0 // unlimited
	DefaultCORSOrigins   = "http://localhost:5173"
	DefaultOSVEndpoint   = "https://api.osv.dev/v1/querybatch"
	DefaultDBMigrate     = true
	DefaultStalenessMult = 2
	// Rate limiting defaults (token bucket per key): strict for
	// unauthenticated entry points, generous for authenticated callers.
	DefaultRateLimitRPS       = 10
	DefaultRateLimitBurst     = 20
	DefaultRateLimitAuthRPS   = 1000
	DefaultRateLimitAuthBurst = 2000
)

// Server is the resolved server configuration.
type Server struct {
	Addr         string
	DBURL        string
	DBMigrate    bool
	CORSOrigins  string
	JWTSecret    string
	LogLevel     string
	InventoryTTL time.Duration
	SSO          SSOConfig
	// TrustedProxies lists the CIDR ranges of reverse proxies (or load
	// balancers) in front of the server. Only requests whose RemoteAddr falls
	// inside one of these ranges may supply X-Forwarded-For / X-Real-IP /
	// X-Forwarded-Proto; empty (the default) means the server never trusts
	// forwarding headers, e.g. when it is deployed directly on the internet.
	TrustedProxies []netip.Prefix
	// Watcher settings. Enable is the master switch; the remaining fields are
	// only validated when Enable is true (a malformed optional setting must
	// not crash a server with the watcher disabled).
	Watcher Watcher
	// RateLimit guards the API against flooding. Disabled by default for
	// dev UX; self-host production enables it via RATE_LIMIT_ENABLED.
	RateLimit RateLimit
}

// SSOConfig configures OIDC single-sign-on login.
type SSOConfig struct {
	Enabled      bool
	ClientID     string
	ClientSecret string
	IssuerURL    string
	RedirectURI  string
	// AllowedDomains gates SSO auto-provisioning: when an IdP subject has
	// no local account, one is created only if the account email domain
	// matches (case-insensitively) an entry here. Empty (the default)
	// disables auto-provisioning entirely — unknown IdP subjects are
	// rejected with 403. Existing local accounts are unaffected.
	AllowedDomains []string
}

// RateLimit is the resolved rate limiter configuration: a strict per-IP
// bucket for unauthenticated entry points and a generous per-caller bucket
// for authenticated requests.
type RateLimit struct {
	Enable    bool
	RPS       int
	Burst     int
	AuthRPS   int
	AuthBurst int
}

// Watcher is the resolved CVE watcher configuration.
type Watcher struct {
	Enable          bool
	PollInterval    time.Duration
	OSVEndpoint     string
	BatchSize       int
	ColdStartWindow time.Duration // zero = full history
	SlackURL        string
	SlackSigning    string
	WebhookURL      string
	WebhookSigning  string
	// Staleness window multiplier is applied by the watcher status surface.
}

// Load reads the server environment, failing on invalid required values.
// Optional watcher settings are parsed eagerly but their errors are only
// reported when the watcher is enabled.
// parseDomainAllowlist splits a comma/space-separated domain allowlist,
// lowercasing and trimming each entry. Empty input yields nil (deny all).
func parseDomainAllowlist(v string) []string {
	var out []string
	for _, part := range strings.FieldsFunc(v, func(c rune) bool { return c == ',' || c == ' ' }) {
		if p := strings.ToLower(strings.TrimSpace(part)); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func Load() (*Server, error) {
	s := &Server{
		Addr:         strOr(os.Getenv("SERVER_ADDR"), DefaultServerAddr),
		DBURL:        os.Getenv("DATABASE_URL"),
		DBMigrate:    strOr(os.Getenv("DB_MIGRATE"), "true") == "true",
		CORSOrigins:  os.Getenv("CORS_ORIGINS"),
		JWTSecret:    os.Getenv("JWT_SECRET"),
		LogLevel:     strOr(os.Getenv("LOG_LEVEL"), "info"),
		InventoryTTL: DefaultInventoryTTL,
	}

	// SSO/OIDC configuration — omitted means SSO is disabled.
	s.SSO = SSOConfig{
		Enabled:        os.Getenv("SSO_ENABLE") == "true",
		ClientID:       os.Getenv("SSO_CLIENT_ID"),
		ClientSecret:   os.Getenv("SSO_CLIENT_SECRET"),
		IssuerURL:      os.Getenv("SSO_ISSUER_URL"),
		RedirectURI:    os.Getenv("SSO_REDIRECT_URI"),
		AllowedDomains: parseDomainAllowlist(os.Getenv("SSO_ALLOWED_DOMAINS")),
	}

	// Reverse-proxy trust: comma/space-separated CIDRs. A proxy inside one of
	// these ranges may set X-Forwarded-* headers; any other peer is treated as
	// the direct client. A malformed CIDR fails startup rather than silently
	// weakening (or unexpectedly strengthening) header trust.
	if v := os.Getenv("TRUSTED_PROXIES"); v != "" {
		for _, part := range strings.FieldsFunc(v, func(c rune) bool { return c == ',' || c == ' ' }) {
			p, err := netip.ParsePrefix(part)
			if err != nil {
				return nil, fmt.Errorf("TRUSTED_PROXIES contains invalid CIDR %q: %w", part, err)
			}
			s.TrustedProxies = append(s.TrustedProxies, p.Masked())
		}
	}

	if v := os.Getenv("INVENTORY_TTL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("INVENTORY_TTL is invalid: %w", err)
		}
		s.InventoryTTL = d
	}

	if s.CORSOrigins == "" {
		s.CORSOrigins = DefaultCORSOrigins
	}

	// Watcher master switch.
	s.Watcher.Enable = os.Getenv("WATCHER_ENABLE") == "true"

	// Rate limiter: off by default; parsed values are validated only when
	// enabled so a stray invalid var cannot crash a dev server.
	s.RateLimit = RateLimit{
		Enable:    os.Getenv("RATE_LIMIT_ENABLED") == "true",
		RPS:       DefaultRateLimitRPS,
		Burst:     DefaultRateLimitBurst,
		AuthRPS:   DefaultRateLimitAuthRPS,
		AuthBurst: DefaultRateLimitAuthBurst,
	}
	var rateLimitErrs []error
	if v := os.Getenv("RATE_LIMIT_RPS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			rateLimitErrs = append(rateLimitErrs, fmt.Errorf("RATE_LIMIT_RPS is invalid: %q", v))
		} else {
			s.RateLimit.RPS = n
		}
	}
	if v := os.Getenv("RATE_LIMIT_BURST"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			rateLimitErrs = append(rateLimitErrs, fmt.Errorf("RATE_LIMIT_BURST is invalid: %q", v))
		} else {
			s.RateLimit.Burst = n
		}
	}
	if v := os.Getenv("RATE_LIMIT_AUTH_RPS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			rateLimitErrs = append(rateLimitErrs, fmt.Errorf("RATE_LIMIT_AUTH_RPS is invalid: %q", v))
		} else {
			s.RateLimit.AuthRPS = n
		}
	}
	if v := os.Getenv("RATE_LIMIT_AUTH_BURST"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			rateLimitErrs = append(rateLimitErrs, fmt.Errorf("RATE_LIMIT_AUTH_BURST is invalid: %q", v))
		} else {
			s.RateLimit.AuthBurst = n
		}
	}
	if s.RateLimit.Enable && len(rateLimitErrs) > 0 {
		return nil, rateLimitErrs[0]
	}

	// Parse watcher optionals; only surface errors when enabled.
	var watcherErrs []error
	s.Watcher.PollInterval = DefaultWatcherPoll
	if v := os.Getenv("WATCHER_POLL_INTERVAL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			watcherErrs = append(watcherErrs, fmt.Errorf("WATCHER_POLL_INTERVAL is invalid: %w", err))
		} else {
			s.Watcher.PollInterval = d
		}
	}
	s.Watcher.OSVEndpoint = strOr(os.Getenv("WATCHER_OSV_ENDPOINT"), DefaultOSVEndpoint)
	if v := os.Getenv("WATCHER_BATCH_SIZE"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			watcherErrs = append(watcherErrs, fmt.Errorf("WATCHER_BATCH_SIZE is invalid: %w", err))
		} else {
			s.Watcher.BatchSize = n
		}
	}
	if w := os.Getenv("WATCHER_COLD_START_WINDOW"); w != "" && w != "full" {
		d, err := time.ParseDuration(w)
		if err != nil {
			watcherErrs = append(watcherErrs, fmt.Errorf("WATCHER_COLD_START_WINDOW is invalid: %w", err))
		} else {
			s.Watcher.ColdStartWindow = d
		}
	}
	s.Watcher.SlackURL = os.Getenv("WATCHER_SLACK_URL")
	s.Watcher.SlackSigning = os.Getenv("WATCHER_SLACK_SIGNING_SECRET")
	s.Watcher.WebhookURL = os.Getenv("WATCHER_WEBHOOK_URL")
	s.Watcher.WebhookSigning = os.Getenv("WATCHER_WEBHOOK_SIGNING_SECRET")

	if s.Watcher.Enable && len(watcherErrs) > 0 {
		return nil, watcherErrs[0]
	}
	return s, nil
}

// WatcherConfig validates watcher settings standalone (the CLI backfill path,
// where the watcher is effectively always enabled by invocation).
func WatcherConfig() (*Watcher, error) {
	w := &Watcher{
		Enable:       true,
		PollInterval: DefaultWatcherPoll,
		OSVEndpoint:  strOr(os.Getenv("WATCHER_OSV_ENDPOINT"), DefaultOSVEndpoint),
	}
	if v := os.Getenv("WATCHER_POLL_INTERVAL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("WATCHER_POLL_INTERVAL is invalid: %w", err)
		}
		w.PollInterval = d
	}
	if v := os.Getenv("WATCHER_BATCH_SIZE"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("WATCHER_BATCH_SIZE is invalid: %w", err)
		}
		w.BatchSize = n
	}
	return w, nil
}

func strOr(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// EnvSlackURL/EnvSlackSigningSecret/EnvWebhookURL/EnvWebhookSigningSecret
// are re-exported for the notifier wiring.
const (
	EnvSlackURL             = "WATCHER_SLACK_URL"
	EnvSlackSigningSecret   = "WATCHER_SLACK_SIGNING_SECRET"
	EnvWebhookURL           = "WATCHER_WEBHOOK_URL"
	EnvWebhookSigningSecret = "WATCHER_WEBHOOK_SIGNING_SECRET"
)
