// Package config centralizes environment parsing and defaults for the
// server, the CVE watcher, and CLI watcher subcommands. A malformed optional
// watcher setting must not fail startup when the watcher is disabled; the
// enabled path validates once through Watcher.Load (or Server.Load when the
// server runs the watcher).
package config

import (
	"fmt"
	"os"
	"strconv"
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
	// Watcher settings. Enable is the master switch; the remaining fields are
	// only validated when Enable is true (a malformed optional setting must
	// not crash a server with the watcher disabled).
	Watcher Watcher
}

// SSOConfig configures OIDC single-sign-on login.
type SSOConfig struct {
	Enabled      bool
	ClientID     string
	ClientSecret string
	IssuerURL    string
	RedirectURI  string
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
		Enabled:      os.Getenv("SSO_ENABLE") == "true",
		ClientID:     os.Getenv("SSO_CLIENT_ID"),
		ClientSecret: os.Getenv("SSO_CLIENT_SECRET"),
		IssuerURL:    os.Getenv("SSO_ISSUER_URL"),
		RedirectURI:  os.Getenv("SSO_REDIRECT_URI"),
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
