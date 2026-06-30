package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/vulnserve/vulnserve/internal/db"
	"github.com/vulnserve/vulnserve/internal/server"
)

func main() {
	addr := os.Getenv("HTTP_ADDR")
	if addr == "" {
		addr = ":8080"
	}

	dbURL := os.Getenv("DATABASE_URL")
	migrate := os.Getenv("DB_MIGRATE")

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "migrate":
			if dbURL == "" {
				log.Fatal("DATABASE_URL is required")
			}
			if err := db.RunMigrations(dbURL, "migrations"); err != nil {
				log.Fatalf("migration failed: %v", err)
			}
			log.Println("migrations complete")
			return
		case "migrate-down":
			if dbURL == "" {
				log.Fatal("DATABASE_URL is required")
			}
			if err := db.RollbackMigrations(dbURL, "migrations"); err != nil {
				log.Fatalf("rollback failed: %v", err)
			}
			log.Println("rollback complete")
			return
		}
	}

	if migrate == "true" && dbURL != "" {
		if err := db.RunMigrations(dbURL, "migrations"); err != nil {
			log.Fatalf("startup migration failed: %v", err)
		}
	}

	handler := server.NewRouter()

	srv := &http.Server{
		Addr:         addr,
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		log.Printf("server starting on %s", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("shutting down...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("shutdown error: %v", err)
	}
}
