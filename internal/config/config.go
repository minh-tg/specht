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
	DefaultServerAddr   = ":8080"
	DefaultInventoryTTL = 2160 * time.Hour // 90d
	DefaultWatcherPoll  = 6 * time.Hour
	DefaultWatcherBatch = 0 // unlimited
	DefaultCORSOrigins  = "http://localhost:5173"
	DefaultOSVEndpoint  = "https://api.osv.dev/v1/querybatch"
	// DefaultOSVVulnEndpoint fetches full advisory records once
	// querybatch has matched their IDs ({id} is the placeholder).
	DefaultOSVVulnEndpoint = "https://api.osv.dev/v1/vulns/{id}"
	// DefaultEPSSEndpoint and DefaultKEVEndpoint are the public
	// vulnerability-intel feeds; DefaultIntelTTL bounds their cache.
	DefaultEPSSEndpoint = "https://api.first.org/data/v1/epss"
	DefaultKEVEndpoint  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	DefaultIntelTTL     = time.Hour
	DefaultDBMigrate    = true
	// DefaultSweepInterval is how often the analysis/waiver expiry
	// sweepers look for expired rows. Tests shorten it via
	// LIFECYCLE_SWEEP_INTERVAL to observe sweeps in seconds.
	DefaultSweepInterval = 5 * time.Minute
	DefaultStalenessMult = 2
	// Rate limiting defaults (token bucket per key): strict for
	// unauthenticated entry points, generous for authenticated callers, and
	// tightest for login and register, which accept guessable credentials.
	DefaultRateLimitRPS            = 10
	DefaultRateLimitBurst          = 20
	DefaultRateLimitAuthRPS        = 1000
	DefaultRateLimitAuthBurst      = 2000
	DefaultRateLimitLoginPerMinute = 5
	DefaultRateLimitLoginBurst     = 5
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
	// SweepInterval is the period of the analysis-expiry and waiver-expiry
	// background sweepers. Must be positive.
	SweepInterval time.Duration
	SSO           SSOConfig
	// TrustedProxies lists only reverse-proxy hop CIDRs. The nearest trusted
	// proxy must append its observed peer to X-Forwarded-For and overwrite
	// X-Real-IP / X-Forwarded-Proto. Empty (the default) means forwarding
	// headers are never trusted, e.g. when deployed directly on the internet.
	TrustedProxies []netip.Prefix
	// Watcher settings. Enable is the master switch; the remaining fields are
	// only validated when Enable is true (a malformed optional setting must
	// not crash a server with the watcher disabled).
	Watcher Watcher
	// Intel settings: EPSS/KEV feed endpoints and the record cache TTL.
	Intel IntelConfig
	// RateLimit guards the API against flooding. Disabled by default for
	// dev UX; self-host production enables it via RATE_LIMIT_ENABLED.
	RateLimit RateLimit
	// RegistrationDisabled turns off self-service account creation
	// (REGISTRATION_ENABLED=false). It defaults to open because the first
	// administrator has to register before anyone can be promoted; SSO-only
	// and locked-down deployments close it once their admins exist.
	RegistrationDisabled bool
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
	// GroupsClaim names the IdP claim carrying group membership for
	// enterprise role mapping. Empty means "groups".
	GroupsClaim string
	// AdminGroups elevates provisioned SSO accounts to admin when IdP
	// group membership matches (exact, case-sensitive). Empty disables
	// elevation — everyone provisions as member. Existing accounts never
	// change role from IdP groups.
	AdminGroups []string
	// AllowUserInfoOnly enables userinfo-only identity when a provider omits
	// id_token. This insecure downgrade defaults to false; present ID tokens
	// are still strictly verified.
	AllowUserInfoOnly bool
	// AllowUnverifiedEmail lets a first-time SSO login link or provision by an
	// email the provider did not mark verified. It exists for providers that
	// never send email_verified and defaults to false; the login is still
	// bound to the provider's stable subject afterwards.
	AllowUnverifiedEmail bool
}

// RateLimit is the resolved rate limiter configuration: a strict per-IP
// bucket for unauthenticated entry points, a generous per-caller bucket for
// authenticated requests, and a much tighter per-IP bucket (refilled per
// minute) for login and register.
type RateLimit struct {
	Enable         bool
	RPS            int
	Burst          int
	AuthRPS        int
	AuthBurst      int
	LoginPerMinute int
	LoginBurst     int
}

// IntelConfig is the resolved vulnerability-intel configuration.
type IntelConfig struct {
	EPSSBaseURL   string
	KEVCatalogURL string
	TTL           time.Duration
}

// Watcher is the resolved CVE watcher configuration.
type Watcher struct {
	Enable       bool
	PollInterval time.Duration
	OSVEndpoint  string
	// OSVVulnEndpoint is the full-advisory URL template querybatch results
	// resolve through ({id} is substituted); an operator mirror keeps both
	// endpoints inside one trust boundary.
	OSVVulnEndpoint string
	BatchSize       int
	ColdStartWindow time.Duration // zero = full history
	SlackURL        string
	SlackSigning    string
	WebhookURL      string
	WebhookSigning  string
	// Staleness window multiplier is applied by the watcher status surface.
}

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

// parseGroupAllowlist splits a comma/space-separated IdP group list.
// Unlike domains, group names are case-sensitive and preserved verbatim;
// empties are dropped.
func parseGroupAllowlist(v string) []string {
	var out []string
	for _, part := range strings.FieldsFunc(v, func(c rune) bool { return c == ',' || c == ' ' }) {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// loadSSO reads the SSO/OIDC environment block; omitted means disabled.
func loadSSO() SSOConfig {
	return SSOConfig{
		Enabled:           os.Getenv("SSO_ENABLE") == "true",
		ClientID:          os.Getenv("SSO_CLIENT_ID"),
		ClientSecret:      os.Getenv("SSO_CLIENT_SECRET"),
		IssuerURL:         os.Getenv("SSO_ISSUER_URL"),
		RedirectURI:       os.Getenv("SSO_REDIRECT_URI"),
		AllowedDomains:    parseDomainAllowlist(os.Getenv("SSO_ALLOWED_DOMAINS")),
		GroupsClaim:       strings.TrimSpace(os.Getenv("SSO_GROUPS_CLAIM")),
		AdminGroups:       parseGroupAllowlist(os.Getenv("SSO_ADMIN_GROUPS")),
		AllowUserInfoOnly: os.Getenv("SSO_ALLOW_USERINFO_ONLY") == "true",

		AllowUnverifiedEmail: os.Getenv("SSO_ALLOW_UNVERIFIED_EMAIL") == "true",
	}
}

// parseTrustedProxies parses comma/space-separated CIDRs. A malformed CIDR
// fails startup rather than silently weakening (or unexpectedly
// strengthening) header trust.
func parseTrustedProxies(v string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, part := range strings.FieldsFunc(v, func(c rune) bool { return c == ',' || c == ' ' }) {
		p, err := netip.ParsePrefix(part)
		if err != nil {
			return nil, fmt.Errorf("TRUSTED_PROXIES contains invalid CIDR %q: %w", part, err)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// parsePositiveInt parses a positive-integer env var, reporting the given
// label on failure.
func parsePositiveInt(label, v string) (int, error) {
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("%s is invalid: %q", label, v)
	}
	return n, nil
}

// loadRateLimit reads limiter settings. Values are validated only when
// enabled so a stray invalid var cannot crash a dev server.
func loadRateLimit(s *Server) error {
	s.RateLimit = RateLimit{
		Enable:         os.Getenv("RATE_LIMIT_ENABLED") == "true",
		RPS:            DefaultRateLimitRPS,
		Burst:          DefaultRateLimitBurst,
		AuthRPS:        DefaultRateLimitAuthRPS,
		AuthBurst:      DefaultRateLimitAuthBurst,
		LoginPerMinute: DefaultRateLimitLoginPerMinute,
		LoginBurst:     DefaultRateLimitLoginBurst,
	}
	parsed := []struct {
		label string
		v     string
		set   func(int)
	}{
		{"RATE_LIMIT_RPS", os.Getenv("RATE_LIMIT_RPS"), func(n int) { s.RateLimit.RPS = n }},
		{"RATE_LIMIT_BURST", os.Getenv("RATE_LIMIT_BURST"), func(n int) { s.RateLimit.Burst = n }},
		{"RATE_LIMIT_AUTH_RPS", os.Getenv("RATE_LIMIT_AUTH_RPS"), func(n int) { s.RateLimit.AuthRPS = n }},
		{"RATE_LIMIT_AUTH_BURST", os.Getenv("RATE_LIMIT_AUTH_BURST"), func(n int) { s.RateLimit.AuthBurst = n }},
		{"RATE_LIMIT_LOGIN_PER_MINUTE", os.Getenv("RATE_LIMIT_LOGIN_PER_MINUTE"), func(n int) { s.RateLimit.LoginPerMinute = n }},
		{"RATE_LIMIT_LOGIN_BURST", os.Getenv("RATE_LIMIT_LOGIN_BURST"), func(n int) { s.RateLimit.LoginBurst = n }},
	}
	for _, p := range parsed {
		if p.v == "" {
			continue
		}
		n, err := parsePositiveInt(p.label, p.v)
		if err != nil {
			if s.RateLimit.Enable {
				return err
			}
			continue
		}
		p.set(n)
	}
	return nil
}

// loadWatcher reads watcher settings; parse errors surface only when the
// watcher is enabled (a malformed optional must not crash a server that
// never runs the watcher).
func loadWatcher(s *Server) error {
	s.Watcher.Enable = os.Getenv("WATCHER_ENABLE") == "true"
	s.Watcher.PollInterval = DefaultWatcherPoll
	s.Watcher.OSVEndpoint = strOr(os.Getenv("WATCHER_OSV_ENDPOINT"), DefaultOSVEndpoint)
	s.Watcher.OSVVulnEndpoint = strOr(os.Getenv("WATCHER_OSV_VULN_ENDPOINT"), DefaultOSVVulnEndpoint)
	s.Watcher.SlackURL = os.Getenv("WATCHER_SLACK_URL")
	s.Watcher.SlackSigning = os.Getenv("WATCHER_SLACK_SIGNING_SECRET")
	s.Watcher.WebhookURL = os.Getenv("WATCHER_WEBHOOK_URL")
	s.Watcher.WebhookSigning = os.Getenv("WATCHER_WEBHOOK_SIGNING_SECRET")

	var errs []error
	if v := os.Getenv("WATCHER_POLL_INTERVAL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("WATCHER_POLL_INTERVAL is invalid: %w", err))
		} else {
			s.Watcher.PollInterval = d
		}
	}
	if v := os.Getenv("WATCHER_BATCH_SIZE"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("WATCHER_BATCH_SIZE is invalid: %w", err))
		} else {
			s.Watcher.BatchSize = n
		}
	}
	if w := os.Getenv("WATCHER_COLD_START_WINDOW"); w != "" && w != "full" {
		d, err := time.ParseDuration(w)
		if err != nil {
			errs = append(errs, fmt.Errorf("WATCHER_COLD_START_WINDOW is invalid: %w", err))
		} else {
			s.Watcher.ColdStartWindow = d
		}
	}
	if s.Watcher.Enable && len(errs) > 0 {
		return errs[0]
	}
	return nil
}

// Load reads the server environment, failing on invalid required values.
// Optional watcher settings are parsed eagerly but their errors are only
// reported when the watcher is enabled.
func Load() (*Server, error) {
	s := &Server{
		Addr:          strOr(os.Getenv("SERVER_ADDR"), DefaultServerAddr),
		DBURL:         os.Getenv("DATABASE_URL"),
		DBMigrate:     strOr(os.Getenv("DB_MIGRATE"), "true") == "true",
		CORSOrigins:   strOr(os.Getenv("CORS_ORIGINS"), DefaultCORSOrigins),
		JWTSecret:     os.Getenv("JWT_SECRET"),
		LogLevel:      strOr(os.Getenv("LOG_LEVEL"), "info"),
		InventoryTTL:  DefaultInventoryTTL,
		SweepInterval: DefaultSweepInterval,
		SSO:           loadSSO(),
	}

	if v := os.Getenv("TRUSTED_PROXIES"); v != "" {
		proxies, err := parseTrustedProxies(v)
		if err != nil {
			return nil, err
		}
		s.TrustedProxies = proxies
	}

	if v := os.Getenv("INVENTORY_TTL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("INVENTORY_TTL is invalid: %w", err)
		}
		s.InventoryTTL = d
	}

	if v := os.Getenv("LIFECYCLE_SWEEP_INTERVAL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			return nil, fmt.Errorf("LIFECYCLE_SWEEP_INTERVAL must be a positive duration, got %q", v)
		}
		s.SweepInterval = d
	}

	if v := os.Getenv("REGISTRATION_ENABLED"); v != "" {
		// Strict on purpose: a typo must fail at startup, never silently
		// leave an intended-closed registration endpoint open.
		enabled, err := strconv.ParseBool(v)
		if err != nil {
			return nil, fmt.Errorf("REGISTRATION_ENABLED is invalid: %q (want true or false)", v)
		}
		s.RegistrationDisabled = !enabled
	}

	if err := loadRateLimit(s); err != nil {
		return nil, err
	}
	if err := loadWatcher(s); err != nil {
		return nil, err
	}
	if err := loadIntel(s); err != nil {
		return nil, err
	}
	return s, nil
}

// loadIntel resolves the EPSS/KEV feed endpoints and cache TTL. A malformed
// TTL is a hard error: intel config is small and explicit, never silently
// defaulted after an operator typo.
func loadIntel(s *Server) error {
	s.Intel = IntelConfig{
		EPSSBaseURL:   strOr(os.Getenv("INTEL_EPSS_ENDPOINT"), DefaultEPSSEndpoint),
		KEVCatalogURL: strOr(os.Getenv("INTEL_KEV_ENDPOINT"), DefaultKEVEndpoint),
		TTL:           DefaultIntelTTL,
	}
	if v := os.Getenv("INTEL_TTL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("INTEL_TTL is invalid: %w", err)
		}
		s.Intel.TTL = d
	}
	return nil
}

// WatcherConfig validates watcher settings standalone (the CLI backfill path,
// where the watcher is effectively always enabled by invocation).
func WatcherConfig() (*Watcher, error) {
	w := &Watcher{
		Enable:          true,
		PollInterval:    DefaultWatcherPoll,
		OSVEndpoint:     strOr(os.Getenv("WATCHER_OSV_ENDPOINT"), DefaultOSVEndpoint),
		OSVVulnEndpoint: strOr(os.Getenv("WATCHER_OSV_VULN_ENDPOINT"), DefaultOSVVulnEndpoint),
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
