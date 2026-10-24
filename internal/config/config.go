// Package config centralizes environment parsing and defaults for the
// server, the CVE watcher, and CLI watcher subcommands. A malformed optional
// watcher setting must not fail startup when the watcher is disabled; the
// enabled path validates once through Watcher.Load (or Server.Load when the
// server runs the watcher).
package config

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/minh-tg/specht/internal/netutil"
)

// Defaults shared by the server, watcher, and CLI.
const (
	DefaultServerAddr   = ":8080"
	DefaultInventoryTTL = 2160 * time.Hour // 90d
	DefaultWatcherPoll  = 6 * time.Hour
	DefaultWatcherBatch = 0 // unlimited
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
	// DefaultDBConnectTimeout is how long startup waits for the database to
	// answer before giving up.
	DefaultDBConnectTimeout = 30 * time.Second
	// DefaultDBMaxConns and DefaultDBMinConns size the database pool. The
	// maximum must stay below the database server's max_connections.
	DefaultDBMaxConns = 20
	DefaultDBMinConns = 2
	// DefaultShutdownTimeout is how long shutdown waits for in-flight
	// requests. It exceeds the longest an ingest may run (two minutes plus
	// the time to write the response), so a stop does not cut one off.
	DefaultShutdownTimeout = 150 * time.Second
	// DefaultSweepInterval is how often the analysis/waiver expiry
	// sweepers look for expired rows. Tests shorten it via
	// LIFECYCLE_SWEEP_INTERVAL to observe sweeps in seconds.
	DefaultSweepInterval = 5 * time.Minute
	// DefaultSessionMaxAge is the absolute lifetime of a sign-in. Refresh
	// tokens rotate for this long after the original login, then the user
	// signs in again.
	DefaultSessionMaxAge = 30 * 24 * time.Hour
	// DefaultRawRetentionDays is how long a report keeps its raw_data
	// payload. The sweep clears older payloads; the report row and its
	// findings stay. Zero keeps every payload.
	DefaultRawRetentionDays = 30
	// MaxRawRetentionDays caps RAW_RETENTION_DAYS at 100 years. Past about 106751 days a
	// time.Duration product overflows, which would push the sweep cutoff into the future.
	MaxRawRetentionDays = 36500
	// MinFingerprintKeyBytes is the shortest FINGERPRINT_KEY accepted.
	MinFingerprintKeyBytes = 16
	DefaultStalenessMult   = 2
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
	Addr      string
	DBURL     string
	DBMigrate bool
	// DBConnectTimeout is how long startup waits for the database. Zero
	// means a single attempt.
	DBConnectTimeout time.Duration
	// DBMaxConns and DBMinConns size the database pool.
	DBMaxConns int
	DBMinConns int
	// ShutdownTimeout is how long a stop waits for in-flight requests.
	ShutdownTimeout time.Duration
	CORSOrigins     string
	JWTSecret       string
	// FingerprintKey is FINGERPRINT_KEY decoded from hex. When set, scanners hash
	// secrets with it and the server never stores a key in the database. Empty
	// means the key is made on first use and kept in instance_secrets.
	FingerprintKey []byte
	LogLevel       string
	InventoryTTL   time.Duration
	// SweepInterval is the period of the analysis-expiry and waiver-expiry
	// background sweepers. Must be positive.
	SweepInterval time.Duration
	// SessionMaxAge is the absolute session lifetime (SESSION_MAX_AGE).
	// Must be positive.
	SessionMaxAge time.Duration
	// RawRetentionDays is how many days a report keeps its raw_data
	// (RAW_RETENTION_DAYS). Zero disables the sweep. Never negative.
	RawRetentionDays int
	SSO              SSOConfig
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
	// (REGISTRATION_ENABLED=false). It defaults to closed; first-run setup
	// creates the initial administrator, and invite links remain available.
	RegistrationDisabled bool
	// IngestConcurrency caps report ingests processed at once; zero leaves
	// the server's built-in default.
	IngestConcurrency int
	// IngestMaxFindings caps the findings and packages one report may
	// produce; zero leaves the built-in default of 100000.
	IngestMaxFindings int
	// IngestMemoryBudget is the memory, in bytes, that all ingests in flight
	// may charge together; each charges 64 bytes per byte of its report. Zero
	// leaves the server's built-in default of 2 GiB.
	IngestMemoryBudget int64
	// CVEDetail configures the external CVE detail providers. They are off
	// unless CVE_DETAIL_PROVIDERS is set.
	CVEDetail CVEDetailConfig
}

// SSOConfig configures OIDC single-sign-on login.
type SSOConfig struct {
	Enabled      bool
	ClientID     string
	ClientSecret string
	// PublicClient allows an empty ClientSecret, for an IdP client registered
	// as public. Without it an empty secret is refused at startup: a
	// confidential client with no secret is almost always a missing variable.
	PublicClient bool
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
	// AdminGroups elevates passwordless SSO accounts to admin when IdP
	// group membership matches (exact, case-sensitive). Empty disables
	// elevation — everyone provisions as member. An account with a local
	// password keeps its local role.
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
	// Enabled is false when INTEL_ENABLED turns the feeds off. Air-gapped
	// installs set it so the server makes no EPSS or KEV calls.
	Enabled       bool
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
		PublicClient:      os.Getenv("SSO_PUBLIC_CLIENT") == "true",
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

// byteUnits maps the size suffixes parseByteSize accepts, lower-cased, to their
// number of bytes. KiB, MiB, GiB and TiB are powers of 1024; KB, MB, GB and TB
// are powers of 1000.
var byteUnits = map[string]float64{
	"b":   1,
	"kib": 1 << 10, "mib": 1 << 20, "gib": 1 << 30, "tib": 1 << 40,
	"kb": 1e3, "mb": 1e6, "gb": 1e9, "tb": 1e12,
}

// parseByteSize parses a positive size in bytes: a whole number of bytes ("2147483648")
// or a number with a unit ("2GiB", "512MiB", "1.5GiB", "250MB"), reporting the given
// label on failure.
func parseByteSize(label, v string) (int64, error) {
	invalid := fmt.Errorf("%s is invalid: %q (want bytes or a size such as 2GiB or 512MiB)", label, v)
	text := strings.ToLower(strings.TrimSpace(v))
	digits := strings.TrimRight(text, "abcdefghijklmnopqrstuvwxyz ")
	unit := strings.TrimSpace(text[len(digits):])
	digits = strings.TrimSpace(digits)
	if digits == "" || strings.Trim(digits, "0123456789.") != "" || strings.Count(digits, ".") > 1 {
		return 0, invalid
	}
	scale := 1.0
	if unit != "" {
		var ok bool
		if scale, ok = byteUnits[unit]; !ok {
			return 0, invalid
		}
	} else if strings.Contains(digits, ".") {
		return 0, invalid
	}
	n, err := strconv.ParseFloat(digits, 64)
	if err != nil {
		return 0, invalid
	}
	size := n * scale
	if size < 1 || size >= math.MaxInt64 {
		return 0, invalid
	}
	return int64(size), nil
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
		Addr:                 strOr(os.Getenv("SERVER_ADDR"), DefaultServerAddr),
		DBURL:                os.Getenv("DATABASE_URL"),
		DBMigrate:            strOr(os.Getenv("DB_MIGRATE"), "true") == "true",
		DBConnectTimeout:     DefaultDBConnectTimeout,
		DBMaxConns:           DefaultDBMaxConns,
		DBMinConns:           DefaultDBMinConns,
		ShutdownTimeout:      DefaultShutdownTimeout,
		CORSOrigins:          os.Getenv("CORS_ORIGINS"),
		JWTSecret:            os.Getenv("JWT_SECRET"),
		LogLevel:             strOr(os.Getenv("LOG_LEVEL"), "info"),
		InventoryTTL:         DefaultInventoryTTL,
		SweepInterval:        DefaultSweepInterval,
		SessionMaxAge:        DefaultSessionMaxAge,
		RawRetentionDays:     DefaultRawRetentionDays,
		SSO:                  loadSSO(),
		RegistrationDisabled: true,
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

	if v := os.Getenv("SESSION_MAX_AGE"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			return nil, fmt.Errorf("SESSION_MAX_AGE must be a positive duration such as 720h, got %q", v)
		}
		s.SessionMaxAge = d
	}

	if v := strings.TrimSpace(os.Getenv("FINGERPRINT_KEY")); v != "" {
		key, err := hex.DecodeString(v)
		if err != nil || len(key) < MinFingerprintKeyBytes {
			return nil, fmt.Errorf("FINGERPRINT_KEY must be hex that decodes to at least %d bytes (for example the output of openssl rand -hex 32)", MinFingerprintKeyBytes)
		}
		s.FingerprintKey = key
	}

	if v := os.Getenv("RAW_RETENTION_DAYS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("RAW_RETENTION_DAYS must be a whole number of days, 0 or more (0 keeps every raw report), got %q", v)
		}
		if n > MaxRawRetentionDays {
			return nil, fmt.Errorf("RAW_RETENTION_DAYS must be at most %d days (100 years), got %q", MaxRawRetentionDays, v)
		}
		s.RawRetentionDays = n
	}

	if v := os.Getenv("DB_CONNECT_TIMEOUT"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < 0 {
			return nil, fmt.Errorf("DB_CONNECT_TIMEOUT must be a duration such as 30s (0s tries once), got %q", v)
		}
		s.DBConnectTimeout = d
	}

	if v := os.Getenv("DB_MAX_CONNS"); v != "" {
		n, err := parsePositiveInt("DB_MAX_CONNS", v)
		if err != nil {
			return nil, err
		}
		s.DBMaxConns = n
	}
	if v := os.Getenv("DB_MIN_CONNS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("DB_MIN_CONNS must be zero or a positive integer, got %q", v)
		}
		s.DBMinConns = n
	}
	if v := os.Getenv("SHUTDOWN_TIMEOUT"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("SHUTDOWN_TIMEOUT must be a duration such as 150s: %w", err)
		}
		s.ShutdownTimeout = d
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

	if v := os.Getenv("INGEST_MAX_CONCURRENCY"); v != "" {
		n, err := parsePositiveInt("INGEST_MAX_CONCURRENCY", v)
		if err != nil {
			return nil, err
		}
		s.IngestConcurrency = n
	}

	if v := os.Getenv("INGEST_MAX_FINDINGS"); v != "" {
		n, err := parsePositiveInt("INGEST_MAX_FINDINGS", v)
		if err != nil {
			return nil, err
		}
		s.IngestMaxFindings = n
	}

	if v := os.Getenv("INGEST_MEMORY_BUDGET"); v != "" {
		n, err := parseByteSize("INGEST_MEMORY_BUDGET", v)
		if err != nil {
			return nil, err
		}
		s.IngestMemoryBudget = n
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
	if err := loadCVEDetail(s); err != nil {
		return nil, err
	}
	return s, nil
}

// loadIntel resolves the EPSS/KEV on/off switch, feed endpoints and cache TTL. A malformed
// TTL is a hard error: intel config is small and explicit, never silently
// defaulted after an operator typo.
func loadIntel(s *Server) error {
	s.Intel = IntelConfig{
		Enabled:       true,
		EPSSBaseURL:   strOr(os.Getenv("INTEL_EPSS_ENDPOINT"), DefaultEPSSEndpoint),
		KEVCatalogURL: strOr(os.Getenv("INTEL_KEV_ENDPOINT"), DefaultKEVEndpoint),
		TTL:           DefaultIntelTTL,
	}
	if v := os.Getenv("INTEL_ENABLED"); v != "" {
		// Strict on purpose: a typo must fail at startup, never silently
		// leave an intended-off outbound feed on.
		enabled, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("INTEL_ENABLED is invalid: %q (want true or false)", v)
		}
		s.Intel.Enabled = enabled
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

// Validate checks the settings Load cannot reject on its own because a test or
// a subcommand may build a Server without them. The server calls it at
// startup, and it reports every problem together so one attempt shows
// everything to fix instead of one error per restart.
func (s *Server) Validate() error {
	var problems []error
	if s.DBURL == "" {
		problems = append(problems, errors.New("DATABASE_URL is required"))
	}
	switch strings.ToLower(s.LogLevel) {
	case "debug", "info", "warn", "error":
	default:
		problems = append(problems, fmt.Errorf("LOG_LEVEL must be debug, info, warn or error, got %q", s.LogLevel))
	}
	if s.InventoryTTL <= 0 {
		problems = append(problems, errors.New("INVENTORY_TTL must be a positive duration"))
	}
	if s.SessionMaxAge <= 0 {
		problems = append(problems, errors.New("SESSION_MAX_AGE must be a positive duration"))
	}
	if s.RawRetentionDays < 0 {
		problems = append(problems, fmt.Errorf("RAW_RETENTION_DAYS must be 0 or more, got %d", s.RawRetentionDays))
	}
	if s.RawRetentionDays > MaxRawRetentionDays {
		problems = append(problems, fmt.Errorf("RAW_RETENTION_DAYS must be at most %d, got %d", MaxRawRetentionDays, s.RawRetentionDays))
	}
	if s.Intel.TTL <= 0 {
		problems = append(problems, errors.New("INTEL_TTL must be a positive duration"))
	}
	if s.DBMaxConns < 1 {
		problems = append(problems, errors.New("DB_MAX_CONNS must be at least 1"))
	}
	if s.DBMinConns < 0 || s.DBMinConns > s.DBMaxConns {
		problems = append(problems, fmt.Errorf("DB_MIN_CONNS must be between 0 and DB_MAX_CONNS (%d), got %d", s.DBMaxConns, s.DBMinConns))
	}
	if s.ShutdownTimeout <= 0 {
		problems = append(problems, errors.New("SHUTDOWN_TIMEOUT must be a positive duration"))
	}
	problems = append(problems, s.SSO.validate()...)
	return errors.Join(problems...)
}

// validate checks the SSO settings an enabled login cannot work without. A
// disabled SSO block is never checked, so stray variables cannot stop a
// server that does not use them.
func (c SSOConfig) validate() []error {
	if !c.Enabled {
		return nil
	}
	var problems []error
	if err := requireURL("SSO_ISSUER_URL", c.IssuerURL); err != nil {
		problems = append(problems, err)
	}
	if strings.TrimSpace(c.ClientID) == "" {
		problems = append(problems, errors.New("SSO_CLIENT_ID is required when SSO_ENABLE=true"))
	}
	if err := requireURL("SSO_REDIRECT_URI", c.RedirectURI); err != nil {
		problems = append(problems, err)
	} else if u, _ := url.Parse(c.RedirectURI); u.Fragment != "" || u.RawFragment != "" {
		problems = append(problems, errors.New("SSO_REDIRECT_URI must not contain a fragment"))
	}
	if c.ClientSecret == "" && !c.PublicClient {
		problems = append(problems, errors.New("SSO_CLIENT_SECRET is required when SSO_ENABLE=true; "+
			"set SSO_PUBLIC_CLIENT=true only if the identity provider client is registered as public"))
	}
	return problems
}

// requireURL checks that raw is an absolute URL with a host that uses https,
// or http when the host is loopback (a local identity provider or a dev
// server). name is the environment variable, used in the error.
func requireURL(name, raw string) error {
	if raw == "" {
		return fmt.Errorf("%s is required when SSO_ENABLE=true", name)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%s is not a valid URL: %w", name, err)
	}
	if u.Host == "" || u.Hostname() == "" {
		return fmt.Errorf("%s must be an absolute URL with a host, got %q", name, raw)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !netutil.IsLoopbackHost(u.Hostname()) {
			return fmt.Errorf("%s must use https unless the host is loopback, got %q", name, raw)
		}
	default:
		return fmt.Errorf("%s must use https, got %q", name, raw)
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
