package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/xMinhx/specht/internal/auth"
	"github.com/xMinhx/specht/internal/db"
	"github.com/xMinhx/specht/internal/lifecycle"
	"github.com/xMinhx/specht/internal/parser"
	"github.com/xMinhx/specht/internal/repo"
	"github.com/xMinhx/specht/internal/scanner"
	"github.com/xMinhx/specht/internal/server"
	"github.com/xMinhx/specht/internal/usecase"
)

func main() {
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

	addr := os.Getenv("SERVER_ADDR")
	if addr == "" {
		addr = ":8080"
	}

	dbURL := os.Getenv("DATABASE_URL")
	migrate := os.Getenv("DB_MIGRATE")
	corsOrigins := os.Getenv("CORS_ORIGINS")

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "migrate":
			if dbURL == "" {
				slog.Error("DATABASE_URL is required")
				os.Exit(1)
			}
			if err := db.RunMigrations(dbURL, "migrations"); err != nil {
				slog.Error("migration failed", "error", err)
				os.Exit(1)
			}
			slog.Info("migrations complete")
			return
		case "migrate-down":
			if dbURL == "" {
				slog.Error("DATABASE_URL is required")
				os.Exit(1)
			}
			if err := db.RollbackMigrations(dbURL, "migrations"); err != nil {
				slog.Error("rollback failed", "error", err)
				os.Exit(1)
			}
			slog.Info("rollback complete")
			return
		}
	}

	if migrate == "true" && dbURL != "" {
		if err := db.RunMigrations(dbURL, "migrations"); err != nil {
			slog.Error("startup migration failed", "error", err)
			os.Exit(1)
		}
	}

	pool, err := db.ConnectPool(context.Background(), dbURL)
	if err != nil {
		slog.Error("connect db", "error", err)
		os.Exit(1)
	}
	defer pool.Close()

	reg := scanner.NewRegistry()
	parser.RegisterAll(reg)

	jwtSecret := os.Getenv("JWT_SECRET")

	jwtAuth, err := auth.NewJWTAuthenticator(jwtSecret)
	if err != nil {
		slog.Error("auth setup", "error", err)
		os.Exit(1)
	}

	repos := repo.NewRepos(pool)

	// Start background daemons
	go lifecycle.RunWaiverExpiry(context.Background(), pool, 5*time.Minute, slog.Default())
	go lifecycle.RunAnalysisExpiry(context.Background(), pool, 5*time.Minute, slog.Default())

	uc := usecase.New(usecase.Deps{
		Repos:    repos,
		Registry: reg,
		JWTAuth:  jwtAuth,
	})

	handler := server.NewRouter(server.RouterConfig{
		Usecases:    uc,
		CORSOrigins: corsOrigins,
		JWTAuth:     jwtAuth,
		APIKeyLookup: func(ctx context.Context, keyHash string) (string, string, error) {
			key, err := repos.APIKeys.GetByHash(ctx, keyHash)
			if err != nil {
				return "", "", fmt.Errorf("key not found")
			}
			if key.RevokedAt.Valid {
				return "", "", fmt.Errorf("key revoked")
			}
			return uuid.UUID(key.ID.Bytes).String(), uuid.UUID(key.ProjectID.Bytes).String(), nil
		},
	})

	srv := &http.Server{
		Addr:         addr,
		Handler:      spaHandler(handler),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		slog.Info("server starting", "addr", addr)
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
