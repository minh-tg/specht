package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/xMinhx/specht/internal/auth"
	"github.com/xMinhx/specht/internal/db"
	"github.com/xMinhx/specht/internal/db/sqlc"
	"github.com/xMinhx/specht/internal/lifecycle"
	"github.com/xMinhx/specht/internal/parser"
	"github.com/xMinhx/specht/internal/repo"
	"github.com/xMinhx/specht/internal/scanner"
	"github.com/xMinhx/specht/internal/server"
	"github.com/xMinhx/specht/internal/usecase"
	"github.com/xMinhx/specht/internal/watcher"
)

func main() {
	setupLogging()

	cfg := loadConfig()
	if handled := handleSubcommand(cfg); handled {
		return
	}

	if cfg.migrate && cfg.dbURL != "" {
		if err := db.RunMigrations(cfg.dbURL, "migrations"); err != nil {
			slog.Error("startup migration failed", "error", err)
			os.Exit(1)
		}
	}

	pool, err := db.ConnectPool(context.Background(), cfg.dbURL)
	if err != nil {
		slog.Error("connect db", "error", err)
		os.Exit(1)
	}
	defer pool.Close()

	reg := scanner.NewRegistry()
	parser.RegisterAll(reg)

	jwtAuth, err := auth.NewJWTAuthenticator(cfg.jwtSecret)
	if err != nil {
		slog.Error("auth setup", "error", err)
		os.Exit(1)
	}

	repos := repo.NewRepos(pool)

	// Start background daemons
	go lifecycle.RunWaiverExpiry(context.Background(), pool, 5*time.Minute, slog.Default())
	go lifecycle.RunAnalysisExpiry(context.Background(), pool, 5*time.Minute, slog.Default())

	uc := usecase.New(usecase.Deps{
		Repos:        repos,
		Registry:     reg,
		JWTAuth:      jwtAuth,
		InventoryTTL: cfg.inventoryTTL,
	})

	handler := server.NewRouter(server.RouterConfig{
		Usecases:    uc,
		CORSOrigins: cfg.corsOrigins,
		JWTAuth:     jwtAuth,
		APIKeyLookup: func(ctx context.Context, keyHash string) (string, string, error) {
			key, err := repos.APIKeys.GetByHash(ctx, keyHash)
			if err != nil {
				return "", "", fmt.Errorf("key not found")
			}
			if key.RevokedAt.Valid {
				return "", "", fmt.Errorf("key revoked")
			}
			actorID := ""
			if key.CreatedBy.Valid {
				actorID = uuid.UUID(key.CreatedBy.Bytes).String()
			}
			return actorID, uuid.UUID(key.ProjectID.Bytes).String(), nil
		},
	})

	srv := &http.Server{
		Addr:         cfg.addr,
		Handler:      spaHandler(handler),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Start the CVE watcher daemon on the same context so it shuts down with
	// the server. Off by default; enable with WATCHER_ENABLE=true. All
	// WATCHER_* variables are parsed inside the gate, so malformed values can
	// never crash a server with the watcher disabled.
	if cfg.watcherEnable {
		runWatcherDaemon(ctx, repos, cfg)
	}

	go func() {
		slog.Info("server starting", "addr", cfg.addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	slog.Info("shutting down...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("shutdown error", "error", err)
	}
}

// config holds every server setting resolved from the environment.
type config struct {
	addr          string
	dbURL         string
	migrate       bool
	corsOrigins   string
	jwtSecret     string
	inventoryTTL  time.Duration
	watcherEnable bool
}

// setupLogging configures the default slog logger from LOG_LEVEL.
func setupLogging() {
	level := slog.LevelInfo
	switch os.Getenv("LOG_LEVEL") {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level})))
}

// loadConfig reads the server environment configuration, exiting on invalid
// values.
func loadConfig() config {
	addr := os.Getenv("SERVER_ADDR")
	if addr == "" {
		addr = ":8080"
	}

	inventoryTTLStr := os.Getenv("INVENTORY_TTL")
	if inventoryTTLStr == "" {
		inventoryTTLStr = "2160h" // 90d — design spec default; stale inventory dropped from watcher matching
	}
	inventoryTTL, err := time.ParseDuration(inventoryTTLStr)
	if err != nil {
		slog.Error("INVENTORY_TTL is invalid", "value", inventoryTTLStr, "error", err)
		os.Exit(1)
	}

	return config{
		addr:          addr,
		dbURL:         os.Getenv("DATABASE_URL"),
		migrate:       os.Getenv("DB_MIGRATE") == "true",
		corsOrigins:   os.Getenv("CORS_ORIGINS"),
		jwtSecret:     os.Getenv("JWT_SECRET"),
		inventoryTTL:  inventoryTTL,
		watcherEnable: os.Getenv("WATCHER_ENABLE") == "true",
	}
}

// handleSubcommand runs the standalone CLI subcommands (migrate,
// migrate-down) and reports whether one was handled.
func handleSubcommand(cfg config) bool {
	if len(os.Args) < 2 {
		return false
	}
	switch os.Args[1] {
	case "migrate":
		if cfg.dbURL == "" {
			slog.Error("DATABASE_URL is required")
			os.Exit(1)
		}
		if err := db.RunMigrations(cfg.dbURL, "migrations"); err != nil {
			slog.Error("migration failed", "error", err)
			os.Exit(1)
		}
		slog.Info("migrations complete")
		return true
	case "migrate-down":
		if cfg.dbURL == "" {
			slog.Error("DATABASE_URL is required")
			os.Exit(1)
		}
		if err := db.RollbackMigrations(cfg.dbURL, "migrations"); err != nil {
			slog.Error("rollback failed", "error", err)
			os.Exit(1)
		}
		slog.Info("rollback complete")
		return true
	}
	return false
}

// runWatcherDaemon starts the CVE watcher poll loop. All WATCHER_* variables
// are parsed here, inside the enable gate, so malformed values can never
// crash a server with the watcher disabled.
func runWatcherDaemon(ctx context.Context, repos *repo.Repos, cfg config) {
	watcherPollIntervalStr := os.Getenv("WATCHER_POLL_INTERVAL")
	if watcherPollIntervalStr == "" {
		watcherPollIntervalStr = "6h" // design spec default
	}
	watcherPollInterval, err := time.ParseDuration(watcherPollIntervalStr)
	if err != nil {
		slog.Error("WATCHER_POLL_INTERVAL is invalid", "value", watcherPollIntervalStr, "error", err)
		os.Exit(1)
	}

	watcherOSVEndpoint := os.Getenv("WATCHER_OSV_ENDPOINT")
	if watcherOSVEndpoint == "" {
		watcherOSVEndpoint = watcher.DefaultOSVEndpoint
	}

	watcherBatchSize := 0
	if v := os.Getenv("WATCHER_BATCH_SIZE"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			slog.Error("WATCHER_BATCH_SIZE is invalid", "value", v, "error", err)
			os.Exit(1)
		}
		watcherBatchSize = n
	}

	// WATCHER_COLD_START_WINDOW bounds the daemon's first (watermark-less)
	// poll: advisories published before now-window are skipped. The default
	// "full" applies no bound — everything OSV knows about the inventory.
	var watcherSince time.Time
	if window := os.Getenv("WATCHER_COLD_START_WINDOW"); window != "" && window != "full" {
		d, err := time.ParseDuration(window)
		if err != nil {
			slog.Error("WATCHER_COLD_START_WINDOW is invalid", "value", window, "error", err)
			os.Exit(1)
		}
		watcherSince = time.Now().UTC().Add(-d)
	}

	// Notification channel: NewSlackNotifier returns a no-op when no webhook
	// URL is configured, so an unconfigured deployment never sends and never
	// blocks the poll.
	watcherNotifier := watcher.NewSlackNotifier(
		os.Getenv(watcher.EnvSlackURL),
		os.Getenv(watcher.EnvSlackSigningSecret),
		slog.Default(),
	)

	projects, err := repos.Projects.List(ctx)
	if err != nil {
		slog.Error("watcher: list projects", "error", err)
		os.Exit(1)
	}
	// Per-project enable/interval config (migration 000020): watch
	// only cve_watcher_enabled projects and schedule each project independently.
	watched := make([]sqlc.Project, 0, len(projects))
	for _, p := range projects {
		if !p.CveWatcherEnabled {
			continue
		}
		watched = append(watched, p)
	}
	if len(watched) == 0 {
		slog.Info("watcher: no enabled projects")
		return
	}
	projectIDs := make([]pgtype.UUID, len(watched))
	projectNames := make(map[string]string, len(watched))
	projectIntervals := make(map[pgtype.UUID]time.Duration, len(watched))
	for i, p := range watched {
		projectIDs[i] = p.ID
		projectNames[uuid.UUID(p.ID.Bytes).String()] = p.Name
		if p.CveWatcherIntervalSeconds > 0 {
			projectIntervals[p.ID] = time.Duration(p.CveWatcherIntervalSeconds) * time.Second
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
			Store:    watcher.NewPollStore(repos),
			Projects: projectIDs,
			Notifier: watcherNotifier,
			ProjectName: func(ctx context.Context, projectID pgtype.UUID) (string, error) {
				return projectNames[uuid.UUID(projectID.Bytes).String()], nil
			},
			Inventory: func(ctx context.Context, projectID pgtype.UUID, since time.Duration) ([]sqlc.DistinctInventoryRow, error) {
				return repos.Inventory.DistinctInventory(ctx, projectID, repo.IntervalFromDuration(since))
			},
			FindGap: repos.Findings.FindScaFindingIdForPurlAndCve,
			GetWatermark: func(ctx context.Context, projectID pgtype.UUID) (time.Time, bool, error) {
				st, err := repos.Watcher.GetProjectState(ctx, projectID)
				if errors.Is(err, pgx.ErrNoRows) {
					return time.Time{}, false, nil
				}
				if err != nil {
					return time.Time{}, false, err
				}
				return st.LastSuccessfulPollAt.Time, st.LastSuccessfulPollAt.Valid, nil
			},
			SetWatermark: func(ctx context.Context, projectID pgtype.UUID, ts time.Time) error {
				return repos.Watcher.UpsertProjectState(ctx, projectID, ts)
			},
			// Health hooks: record attempt/failure state so operators can
			// see whether the watcher is healthy or failing.
			RecordAttempt: func(ctx context.Context, ts time.Time) error {
				return repos.Watcher.RecordAttempt(ctx, ts)
			},
			RecordFailure: func(ctx context.Context, errText string, ts time.Time) error {
				return repos.Watcher.RecordFailure(ctx, errText, ts)
			},
			RecordSuccess: func(ctx context.Context, ts time.Time) error {
				return repos.Watcher.UpdateState(ctx, ts)
			},
			ResetFailure: repos.Watcher.ResetFailure,
			Logger:       slog.Default(),
			InventoryTTL: cfg.inventoryTTL,
			Since:        watcherSince,
		},
		ProjectIntervals: projectIntervals,
	})
}
