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
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/xMinhx/specht/internal/auth"
	"github.com/xMinhx/specht/internal/config"
	"github.com/xMinhx/specht/internal/db"
	"github.com/xMinhx/specht/internal/lifecycle"
	"github.com/xMinhx/specht/internal/parser"
	"github.com/xMinhx/specht/internal/port"
	"github.com/xMinhx/specht/internal/repo"
	"github.com/xMinhx/specht/internal/scanner"
	"github.com/xMinhx/specht/internal/server"
	"github.com/xMinhx/specht/internal/tracker"
	"github.com/xMinhx/specht/internal/usecase"
	"github.com/xMinhx/specht/internal/watcher"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("config", "error", err)
		os.Exit(1)
	}
	setupLogging(cfg.LogLevel)
	if handled := handleSubcommand(cfg); handled {
		return
	}

	if cfg.DBMigrate && cfg.DBURL != "" {
		if err := db.RunMigrations(cfg.DBURL, "migrations"); err != nil {
			slog.Error("startup migration failed", "error", err)
			os.Exit(1)
		}
	}

	pool, err := db.ConnectPool(context.Background(), cfg.DBURL)
	if err != nil {
		slog.Error("connect db", "error", err)
		os.Exit(1)
	}
	defer pool.Close()

	reg := scanner.NewRegistry()
	for _, s := range parser.Builtins() {
		if err := reg.Register(s); err != nil {
			slog.Error("register scanner", "error", err)
			os.Exit(1)
		}
	}

	jwtAuth, err := auth.NewJWTAuthenticator(cfg.JWTSecret)
	if err != nil {
		slog.Error("auth setup", "error", err)
		os.Exit(1)
	}

	repos := repo.NewRepos(pool)
	stores := repo.NewPortStores(pool)

	uc := usecase.New(usecase.Deps{
		Stores:       stores,
		Registry:     reg,
		Tokens:       jwtAuth,
		Passwords:    auth.NewPasswordHasher(),
		InventoryTTL: cfg.InventoryTTL,
		Tracker:      buildTrackerDispatcher(),
	})

	// SSO is optional: when disabled there is no issuer to validate, and the
	// router treats a nil OIDC authenticator as "SSO off".
	var oidcAuth *auth.OIDCAuthenticator
	if cfg.SSO.Enabled {
		oidcAuth, err = auth.NewOIDCAuthenticator(auth.OIDCConfig{ClientID: cfg.SSO.ClientID, ClientSecret: cfg.SSO.ClientSecret, IssuerURL: cfg.SSO.IssuerURL, RedirectURI: cfg.SSO.RedirectURI}, nil)
		if err != nil {
			slog.Error("auth setup", "error", err)
			os.Exit(1)
		}
	}

	handler := server.NewRouter(server.RouterConfig{
		Usecases:       uc,
		CORSOrigins:    cfg.CORSOrigins,
		TrustedProxies: cfg.TrustedProxies,
		JWTAuth:        jwtAuth,
		APIKeyLookup: func(ctx context.Context, keyHash string) (string, string, []string, time.Time, error) {
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
			// Stamp last_used_at on every successful key authentication. This
			// is best-effort observability: a failure must never deny a key
			// that has already passed every gate.
			if err := repos.APIKeys.TouchLastUsed(ctx, key.ID); err != nil {
				slog.Warn("api key lookup: failed to update last_used_at", "error", err)
			}
			return actorID, uuid.UUID(key.ProjectID.Bytes).String(), scopes, expiresAt, nil
		},
		OIDCEnabled:       cfg.SSO.Enabled,
		OIDC:              oidcAuth,
		SSOAllowedDomains: cfg.SSO.AllowedDomains,
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

	// Lifecycle sweepers: analysis expiry and waiver expiry. Both stop when
	// ctx is cancelled.
	go lifecycle.RunWaiverExpiry(ctx, repo.NewWaiverExpiryStore(pool), 5*time.Minute, slog.Default())
	go lifecycle.RunAnalysisExpiry(ctx, repo.NewAnalysisExpiryStore(pool), 5*time.Minute, slog.Default())

	// Start the CVE watcher daemon on the same context so it shuts down with
	// the server. Off by default; enable with WATCHER_ENABLE=true. All
	// WATCHER_* variables are parsed inside the gate, so malformed values can
	// never crash a server with the watcher disabled.
	if cfg.Watcher.Enable {
		if err := runWatcherDaemon(ctx, stores, cfg); err != nil {
			slog.Error("start watcher daemon", "error", err)
			os.Exit(1)
		}
	}

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
func runWatcherDaemon(ctx context.Context, stores *port.Stores, cfg *config.Server) error {
	watcherPollInterval := cfg.Watcher.PollInterval
	watcherOSVEndpoint := cfg.Watcher.OSVEndpoint
	watcherBatchSize := cfg.Watcher.BatchSize

	// WATCHER_COLD_START_WINDOW bounds the daemon's first (watermark-less)
	// poll: advisories published before now-window are skipped. The default
	// "full" applies no bound — everything OSV knows about the inventory.
	var watcherSince time.Time
	if cfg.Watcher.ColdStartWindow > 0 {
		watcherSince = time.Now().UTC().Add(-cfg.Watcher.ColdStartWindow)
	}

	// Notification channels: each configured channel delivers every batch;
	// no channel configured leaves a nil Notifier, which the daemon treats
	// as a no-op. Failures never propagate by Notifier contract.
	var watcherNotifier watcher.Notifier
	var channels []watcher.Notifier
	if slackURL := os.Getenv(watcher.EnvSlackURL); slackURL != "" {
		channels = append(channels, watcher.NewSlackNotifier(
			slackURL, os.Getenv(watcher.EnvSlackSigningSecret), slog.Default()))
	}
	if webhookURL := os.Getenv(watcher.EnvWebhookURL); webhookURL != "" {
		channels = append(channels, watcher.NewWebhookNotifier(
			webhookURL, os.Getenv(watcher.EnvWebhookSigningSecret), slog.Default()))
	}
	if len(channels) == 1 {
		watcherNotifier = channels[0]
	} else if len(channels) > 1 {
		watcherNotifier = watcher.NewFanoutNotifier(channels...)
	}

	projects, err := stores.Projects.List(ctx)
	if err != nil {
		return fmt.Errorf("watcher: list projects: %w", err)
	}
	// Per-project enable/interval config (migration 000020): watch
	// only cve_watcher_enabled projects and schedule each project independently.
	watched := make([]port.Project, 0, len(projects))
	for _, p := range projects {
		if !p.CveWatcherEnabled {
			continue
		}
		watched = append(watched, p)
	}
	if len(watched) == 0 {
		slog.Info("watcher: no enabled projects")
		return nil
	}
	projectIDs := make([]string, len(watched))
	projectNames := make(map[string]string, len(watched))
	projectIntervals := make(map[string]time.Duration, len(watched))
	for i, p := range watched {
		projectIDs[i] = p.ID
		projectNames[p.ID] = p.Name
		if p.CveWatcherIntervalSecs > 0 {
			projectIntervals[p.ID] = time.Duration(p.CveWatcherIntervalSecs) * time.Second
		} else {
			projectIntervals[p.ID] = watcherPollInterval
		}
	}
	cacheTTL := watcherPollInterval
	if cacheTTL <= 0 {
		cacheTTL = 6 * time.Hour
	}
	for _, interval := range projectIntervals {
		if interval > 0 && interval < cacheTTL {
			cacheTTL = interval
		}
	}

	watcher.RunCveWatcher(ctx, watcher.RunCveWatcherConfig{
		PollInterval: watcherPollInterval,
		PollDeps: watcher.PollDeps{
			Client: watcher.NewHTTPClient(watcher.HTTPClientConfig{
				Endpoint:  watcherOSVEndpoint,
				BatchSize: watcherBatchSize,
				CacheTTL:  cacheTTL,
			}),
			Store:    watcher.NewPollStore(stores),
			Projects: projectIDs,
			Notifier: watcherNotifier,
			ProjectName: func(ctx context.Context, projectID string) (string, error) {
				return projectNames[projectID], nil
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
			Since:        watcherSince,
		},
		ProjectIntervals: projectIntervals,
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
