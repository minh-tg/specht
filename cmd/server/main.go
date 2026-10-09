package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/config"
	"github.com/minh-tg/specht/internal/db"
	"github.com/minh-tg/specht/internal/intel"
	"github.com/minh-tg/specht/internal/lifecycle"
	"github.com/minh-tg/specht/internal/parser"
	"github.com/minh-tg/specht/internal/port"
	"github.com/minh-tg/specht/internal/provider"
	"github.com/minh-tg/specht/internal/repo"
	"github.com/minh-tg/specht/internal/scanner"
	"github.com/minh-tg/specht/internal/server"
	"github.com/minh-tg/specht/internal/tracker"
	"github.com/minh-tg/specht/internal/usecase"
	"github.com/minh-tg/specht/internal/watcher"
)

// exitOnError logs err and terminates with exit code 1; nil is a no-op.
func exitOnError(stage string, err error) {
	if err != nil {
		slog.Error(stage, "error", err)
		os.Exit(1)
	}
}

// connectDB runs configured migrations and opens the pool.
func connectDB(cfg *config.Server) *pgxpool.Pool {
	if cfg.DBMigrate && cfg.DBURL != "" {
		db.WarnInsecureMigrationURL(cfg.DBURL)
		exitOnError("startup migration failed", db.RunMigrations(cfg.DBURL, "migrations"))
	}
	pool, err := db.ConnectPool(context.Background(), cfg.DBURL)
	exitOnError("connect db", err)
	return pool
}

// buildScannerRegistry registers every builtin parser as a scanner adapter.
func buildScannerRegistry() *scanner.Registry {
	reg := scanner.NewRegistry()
	for _, s := range parser.Builtins() {
		exitOnError("register scanner", reg.Register(s))
	}
	return reg
}

// buildProviders assembles the repository provider registry:
// compile-time plugins like scanners — GitHub ships as the first adapter;
// previews plan checks without network I/O or credentials.
func buildProviders() *provider.Registry {
	providers := provider.NewRegistry()
	exitOnError("register provider", providers.Register(provider.NewGitHubProvider()))
	return providers
}

// resolveOIDCAuth builds the OIDC authenticator when SSO is enabled. SSO is
// optional: when disabled there is no issuer to validate, and the router
// treats a nil OIDC authenticator as "SSO off".
func resolveOIDCAuth(cfg *config.Server) *auth.OIDCAuthenticator {
	if !cfg.SSO.Enabled {
		return nil
	}
	oidcAuth, err := auth.NewOIDCAuthenticator(auth.OIDCConfig{ClientID: cfg.SSO.ClientID, ClientSecret: cfg.SSO.ClientSecret, IssuerURL: cfg.SSO.IssuerURL, RedirectURI: cfg.SSO.RedirectURI, GroupsClaim: cfg.SSO.GroupsClaim, AllowUserInfoOnly: cfg.SSO.AllowUserInfoOnly}, nil)
	exitOnError("auth setup", err)
	return oidcAuth
}

// apiKeyLookup adapts the API key repository to the router's lookup
// contract.
func apiKeyLookup(repos *repo.Repos) func(ctx context.Context, keyHash string) (string, string, []string, time.Time, error) {
	touches := newTouchThrottle(apiKeyTouchInterval)
	return func(ctx context.Context, keyHash string) (string, string, []string, time.Time, error) {
		key, err := repos.APIKeys.GetByHash(ctx, keyHash)
		if err != nil {
			return "", "", nil, time.Time{}, fmt.Errorf("key not found")
		}
		if key.RevokedAt.Valid {
			return "", "", nil, time.Time{}, fmt.Errorf("key revoked")
		}
		// An expired key is rejected at lookup time: it must never
		// authenticate, so there is no window where a stale key keeps
		// working. (The authenticator double-checks expiry as well.)
		if key.ExpiresAt.Valid && !key.ExpiresAt.Time.After(time.Now()) {
			return "", "", nil, time.Time{}, fmt.Errorf("key expired")
		}
		actorID := ""
		if key.CreatedBy.Valid {
			actorID = uuid.UUID(key.CreatedBy.Bytes).String()
		}
		scopes, err := apiKeyScopes(key.Scopes)
		if err != nil {
			slog.Warn("api key lookup: unreadable scopes; denying key", "error", err)
			return "", "", nil, time.Time{}, fmt.Errorf("key scopes unreadable")
		}
		expiresAt := time.Time{}
		if key.ExpiresAt.Valid {
			expiresAt = key.ExpiresAt.Time
		}
		// Stamp last_used_at, at most once a minute per key. This is
		// best-effort observability: a failure must never deny a key that
		// has already passed every gate.
		if keyID := uuid.UUID(key.ID.Bytes).String(); touches.due(keyID) {
			if err := repos.APIKeys.TouchLastUsed(ctx, key.ID); err != nil {
				touches.release(keyID)
				slog.Warn("api key lookup: failed to update last_used_at", "error", err)
			}
		}
		return actorID, uuid.UUID(key.ProjectID.Bytes).String(), scopes, expiresAt, nil
	}
}

// startLifecycle starts the analysis/waiver expiry sweepers and, when
// enabled, the CVE watcher daemon — all bound to ctx so they stop with the
// server.
func buildLifecycleStores(pool *pgxpool.Pool) (port.AnalysisExpiryStore, port.WaiverExpiryStore) {
	return repo.NewAnalysisExpiryStore(pool), repo.NewWaiverExpiryStore(pool)
}

func startLifecycle(ctx context.Context, stores *port.Stores, analysisStore port.AnalysisExpiryStore, waiverStore port.WaiverExpiryStore, cfg *config.Server) {
	exitOnError("start waiver expiry daemon", lifecycle.RunWaiverExpiry(ctx, waiverStore, cfg.SweepInterval, slog.Default()))
	exitOnError("start analysis expiry daemon", lifecycle.RunAnalysisExpiry(ctx, analysisStore, cfg.SweepInterval, slog.Default()))
	if cfg.Watcher.Enable {
		exitOnError("start watcher daemon", runWatcherDaemon(ctx, stores, cfg))
	}
}

func main() {
	// The container HEALTHCHECK runs before any configuration is needed, so
	// it must not depend on secrets or the database being set up.
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(healthcheckMain())
	}
	cfg, err := config.Load()
	exitOnError("config", err)
	setupLogging(cfg.LogLevel)
	if warning := insecureDBTransport(cfg.DBURL); warning != "" {
		slog.Warn(warning)
	}
	if handled := handleSubcommand(cfg); handled {
		return
	}

	pool := connectDB(cfg)
	defer pool.Close()

	reg := buildScannerRegistry()
	providers := buildProviders()
	revoker := repo.NewPostgresRevoker(pool)
	jwtAuth, err := auth.NewJWTAuthenticatorWithRevoker(cfg.JWTSecret, revoker)
	exitOnError("auth setup", err)

	repos := repo.NewRepos(pool)
	stores := repo.NewPortStores(pool)
	jwtAuth.WithTokenVersions(stores.Users)

	// Admin elevation path: ADMIN_EMAILS (comma-separated) promotes
	// existing accounts to the global admin role at startup so tenant
	// membership can be administered. Unknown addresses are skipped with a
	// warning; the flag is otherwise a no-op.
	bootstrapAdmins(context.Background(), stores, !cfg.RegistrationDisabled)

	if cfg.SSO.Enabled && cfg.SSO.AllowUnverifiedEmail {
		slog.Warn("SSO_ALLOW_UNVERIFIED_EMAIL is on: a first SSO login may link to an existing account by an email " +
			"the identity provider did not verify; use it only if your provider's emails are administrator-controlled")
	}

	uc := usecase.New(usecase.Deps{
		Stores:                  stores,
		Registry:                reg,
		Providers:               providers,
		Tokens:                  jwtAuth,
		Passwords:               auth.NewPasswordHasher(),
		InventoryTTL:            cfg.InventoryTTL,
		SSOAllowUnverifiedEmail: cfg.SSO.AllowUnverifiedEmail,
		Tracker:                 buildTrackerDispatcher(),
		Intel: intel.NewStore(cfg.Intel.TTL, nil,
			&intel.EPSSProvider{BaseURL: cfg.Intel.EPSSBaseURL},
			&intel.KEVProvider{CatalogURL: cfg.Intel.KEVCatalogURL, TTL: cfg.Intel.TTL}),
	})

	handler := server.NewRouter(server.RouterConfig{
		Usecases:    uc,
		CORSOrigins: cfg.CORSOrigins,

		RegistrationDisabled: cfg.RegistrationDisabled,
		IngestConcurrency:    cfg.IngestConcurrency,
		TrustedProxies:       cfg.TrustedProxies,
		RateLimit: server.RateLimitConfig{
			Enabled:        cfg.RateLimit.Enable,
			RPS:            cfg.RateLimit.RPS,
			Burst:          cfg.RateLimit.Burst,
			AuthRPS:        cfg.RateLimit.AuthRPS,
			AuthBurst:      cfg.RateLimit.AuthBurst,
			LoginPerMinute: cfg.RateLimit.LoginPerMinute,
			LoginBurst:     cfg.RateLimit.LoginBurst,
		},
		JWTAuth:           jwtAuth,
		TokenIssuer:       jwtAuth,
		Revoker:           jwtAuth,
		APIKeyLookup:      apiKeyLookup(repos),
		OIDCEnabled:       cfg.SSO.Enabled,
		OIDC:              resolveOIDCAuth(cfg),
		SSOAllowedDomains: cfg.SSO.AllowedDomains,
		SSOAdminGroups:    cfg.SSO.AdminGroups,
	})

	srv := &http.Server{
		Addr:         cfg.Addr,
		Handler:      spaHandler(handler),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Build the shutdown context before launching any worker: every
	// background goroutine (lifecycle sweepers, CVE watcher) is cancelled by
	// this context so none can keep running on context.Background() after
	// the HTTP server shuts down.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	analysisExpiryStore, waiverExpiryStore := buildLifecycleStores(pool)
	startLifecycle(ctx, stores, analysisExpiryStore, waiverExpiryStore, cfg)

	go func() {
		slog.Info("server starting", "addr", cfg.Addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	slog.Info("shutting down...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Stop accepting HTTP first; the worker goroutines observe ctx.Done() and
	// drain on their own tickers/selects.
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("shutdown error", "error", err)
	}
}

// setupLogging configures the default slog logger from the configured level.
func setupLogging(level string) {
	lvl := slog.LevelInfo
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: lvl})))
}

// handleSubcommand runs the standalone CLI subcommands (migrate,
// migrate-down) and reports whether one was handled.
func handleSubcommand(cfg *config.Server) bool {
	if len(os.Args) < 2 {
		return false
	}
	switch os.Args[1] {
	case "migrate":
		if cfg.DBURL == "" {
			slog.Error("DATABASE_URL is required")
			os.Exit(1)
		}
		if err := db.RunMigrations(cfg.DBURL, "migrations"); err != nil {
			slog.Error("migration failed", "error", err)
			os.Exit(1)
		}
		slog.Info("migrations complete")
		return true
	case "migrate-down":
		if cfg.DBURL == "" {
			slog.Error("DATABASE_URL is required")
			os.Exit(1)
		}
		if err := db.RollbackMigrations(cfg.DBURL, "migrations"); err != nil {
			slog.Error("rollback failed", "error", err)
			os.Exit(1)
		}
		slog.Info("rollback complete")
		return true
	}
	return false
}

// buildTrackerDispatcher wires the tracker event dispatcher from env config.
// Disabled by default (TRACKER_PROVIDER=noop); a no-op dispatcher is returned
// when no provider is configured, so core use cases never need nil checks
// beyond the optional Tracker field.
func buildTrackerDispatcher() *tracker.Dispatcher {
	cfg := tracker.ResolveConfig()
	var tr tracker.Tracker = tracker.NoopTracker{}
	switch cfg.Provider {
	case "inprocess":
		tr = tracker.NewInProcessTracker(func(msg string, args ...any) {
			slog.Debug(msg, args...)
		})
	case "webhook":
		urls := tracker.EnvWebHookURLs("WATCHER_WEBHOOK_URLS", os.Getenv)
		if len(urls) == 0 {
			slog.Warn("webhook tracker enabled but WATCHER_WEBHOOK_URLS is empty; falling back to noop")
			tr = tracker.NoopTracker{}
		} else {
			tr = tracker.NewWebHookTracker(tracker.WebHookTrackerConfig{
				Endpoints: urls,
				Secret:    os.Getenv(tracker.EnvWebHookSecret),
			}, func(msg string, args ...any) { slog.Debug(msg, args...) })
		}
	case "noop", "":
		tr = tracker.NoopTracker{}
	}
	return tracker.NewDispatcher(tr, slog.Default())
}

// runWatcherDaemon starts the CVE watcher poll loop. All WATCHER_* variables
// are parsed here, inside the enable gate, so malformed values can never
// crash a server with the watcher disabled. An error is returned for
// pre-loop setup failures (e.g. the project list cannot be loaded) so the
// caller can abort from the main goroutine instead of inside a watcher
// goroutine.
// bootstrapAdmins promotes ADMIN_EMAILS accounts to global admin.
// It is idempotent and never creates accounts. Registration does not prove
// ownership of an address, so with signup open an address that is not yet
// registered can be claimed by anyone, and the next start would promote
// them; that case is reported as an error rather than a routine skip.
func bootstrapAdmins(ctx context.Context, stores *port.Stores, signupOpen bool) {
	raw := os.Getenv("ADMIN_EMAILS")
	if raw == "" {
		return
	}
	for _, email := range strings.FieldsFunc(raw, func(c rune) bool { return c == ',' || c == ' ' }) {
		email = auth.NormalizeEmail(email)
		if email == "" {
			continue
		}
		user, err := stores.Users.GetByEmail(ctx, email)
		if err != nil {
			if signupOpen {
				slog.Error("admin bootstrap: unknown account and anyone can register it; register it now or set REGISTRATION_ENABLED=false before the next start",
					"email", auth.MaskEmail(email))
			} else {
				slog.Warn("admin bootstrap: unknown account, skipping", "email", auth.MaskEmail(email))
			}
			continue
		}
		if user.Role == auth.RoleAdmin {
			continue
		}
		if _, err := stores.Users.SetRole(ctx, user.ID, auth.RoleAdmin); err != nil {
			slog.Error("admin bootstrap: promotion failed", "email", auth.MaskEmail(email), "error", err)
			continue
		}
		slog.Info("admin bootstrap: promoted to admin", "email", auth.MaskEmail(email))
	}
}

// buildWatcherNotifier assembles the notification fanout from the configured
// channels; each configured channel delivers every batch, and no channel
// configured leaves a nil Notifier, which the daemon treats as a no-op.
// Failures never propagate by Notifier contract.
func buildWatcherNotifier() watcher.Notifier {
	var channels []watcher.Notifier
	if slackURL := os.Getenv(watcher.EnvSlackURL); slackURL != "" {
		channels = append(channels, watcher.NewSlackNotifier(
			slackURL, os.Getenv(watcher.EnvSlackSigningSecret), slog.Default()))
	}
	if webhookURL := os.Getenv(watcher.EnvWebhookURL); webhookURL != "" {
		channels = append(channels, watcher.NewWebhookNotifier(
			webhookURL, os.Getenv(watcher.EnvWebhookSigningSecret), slog.Default()))
	}
	switch len(channels) {
	case 0:
		return nil
	case 1:
		return channels[0]
	default:
		return watcher.NewFanoutNotifier(channels...)
	}
}

// watchedProjects loads the per-project watch schedule (migration 000020):
// only cve_watcher_enabled projects, each with its own interval, plus the
// name map notifications use for display.
func watchedProjects(ctx context.Context, stores *port.Stores, fallbackInterval time.Duration) (ids []string, names map[string]string, intervals map[string]time.Duration, err error) {
	projects, err := stores.Projects.List(ctx)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("watcher: list projects: %w", err)
	}
	names = make(map[string]string, len(projects))
	intervals = make(map[string]time.Duration, len(projects))
	for _, p := range projects {
		if !p.CveWatcherEnabled {
			continue
		}
		ids = append(ids, p.ID)
		names[p.ID] = p.Name
		if p.CveWatcherIntervalSecs > 0 {
			intervals[p.ID] = time.Duration(p.CveWatcherIntervalSecs) * time.Second
		} else {
			intervals[p.ID] = fallbackInterval
		}
	}
	return ids, names, intervals, nil
}

// watcherCacheTTL bounds the OSV HTTP cache to the tightest project
// interval (never below the daemon default).
func watcherCacheTTL(intervals map[string]time.Duration, fallback time.Duration) time.Duration {
	ttl := fallback
	if ttl <= 0 {
		ttl = 6 * time.Hour
	}
	for _, interval := range intervals {
		if interval > 0 && interval < ttl {
			ttl = interval
		}
	}
	return ttl
}

// watcherPollDeps wires the daemon's poll dependencies to the stores.
func watcherPollDeps(stores *port.Stores, cfg *config.Server, ids []string, names map[string]string, notifier watcher.Notifier, cacheTTL time.Duration) watcher.PollDeps {
	// WATCHER_COLD_START_WINDOW bounds the daemon's first (watermark-less)
	// poll: advisories published before now-window are skipped. The default
	// "full" applies no bound — everything OSV knows about the inventory.
	var since time.Time
	if cfg.Watcher.ColdStartWindow > 0 {
		since = time.Now().UTC().Add(-cfg.Watcher.ColdStartWindow)
	}
	return watcher.PollDeps{
		Client: watcher.NewHTTPClient(watcher.HTTPClientConfig{
			Endpoint:     cfg.Watcher.OSVEndpoint,
			VulnEndpoint: cfg.Watcher.OSVVulnEndpoint,
			BatchSize:    cfg.Watcher.BatchSize,
			CacheTTL:     cacheTTL,
		}),
		Store:    watcher.NewPollStore(stores),
		Projects: ids,
		Notifier: notifier,
		ProjectName: func(ctx context.Context, projectID string) (string, error) {
			p, err := stores.Projects.GetByID(ctx, projectID)
			if err == nil && p.Name != "" {
				return p.Name, nil
			}
			if name, ok := names[projectID]; ok {
				return name, nil
			}
			return projectID, nil
		},
		Inventory: func(ctx context.Context, projectID string, since time.Duration) ([]port.InventoryPackage, error) {
			return stores.Inventory.DistinctInventory(ctx, projectID, since)
		},
		FindGap: stores.Findings.FindScaFindingIDForPurlAndCve,
		GetWatermark: func(ctx context.Context, projectID string) (time.Time, bool, error) {
			st, err := stores.Watcher.GetProjectState(ctx, projectID)
			if errors.Is(err, port.ErrNotFound) {
				return time.Time{}, false, nil
			}
			if err != nil {
				return time.Time{}, false, err
			}
			if st.LastSuccessfulPollAt == nil {
				return time.Time{}, false, nil
			}
			return *st.LastSuccessfulPollAt, true, nil
		},
		SetWatermark: func(ctx context.Context, projectID string, ts time.Time) error {
			return stores.Watcher.UpsertProjectState(ctx, projectID, ts)
		},
		// Health hooks: record attempt/failure state so operators can
		// see whether the watcher is healthy or failing.
		RecordAttempt: func(ctx context.Context, ts time.Time) error {
			return stores.Watcher.RecordAttempt(ctx, ts)
		},
		RecordFailure: func(ctx context.Context, errText string, ts time.Time) error {
			return stores.Watcher.RecordFailure(ctx, errText, ts)
		},
		RecordSuccess: func(ctx context.Context, ts time.Time) error {
			return stores.Watcher.UpdateState(ctx, ts)
		},
		ResetFailure: stores.Watcher.ResetFailure,
		Logger:       slog.Default(),
		InventoryTTL: cfg.InventoryTTL,
		Since:        since,
	}
}

func runWatcherDaemon(ctx context.Context, stores *port.Stores, cfg *config.Server) error {
	ids, names, intervals, err := watchedProjects(ctx, stores, cfg.Watcher.PollInterval)
	if err != nil {
		return err
	}
	deps := watcherPollDeps(stores, cfg, ids, names, buildWatcherNotifier(), watcherCacheTTL(intervals, cfg.Watcher.PollInterval))
	watcher.RunCveWatcher(ctx, watcher.RunCveWatcherConfig{
		PollInterval:     cfg.Watcher.PollInterval,
		ReloadProjects:   stores.Projects.List,
		PollDeps:         deps,
		ProjectIntervals: intervals,
		// The schedule is a snapshot; re-check the switch right before each
		// poll so a project disabled mid-round is not polled anyway.
		ProjectEnabled: func(ctx context.Context, projectID string) (bool, error) {
			project, err := stores.Projects.GetByID(ctx, projectID)
			if errors.Is(err, port.ErrNotFound) {
				return false, nil
			}
			if err != nil {
				return false, err
			}
			return project.CveWatcherEnabled, nil
		},
	})
	return nil
}

// apiKeyScopes decodes the stored scopes JSONB column of an API key into the
// scope list the authenticator carries on the identity. Stored keys default
// to ["ingest"] (schema default) and the create path always writes a JSON
// array, but a malformed value must deny the key rather than panic or grant
// implicit permissions: scope enforcement is a security boundary, so an
// unreadable scope column fails closed.
func apiKeyScopes(raw []byte) ([]string, error) {
	scopes := []string{}
	if len(raw) == 0 {
		return scopes, nil
	}
	if err := json.Unmarshal(raw, &scopes); err != nil {
		return nil, fmt.Errorf("decode key scopes: %w", err)
	}
	return scopes, nil
}
