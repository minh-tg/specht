package db

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PoolOptions sizes the connection pool.
type PoolOptions struct {
	// MaxConns is the most connections the pool opens. It must stay below the
	// database server's max_connections, shared with every other client. Zero
	// or less means the default.
	MaxConns int
	// MinConns is how many connections stay open when idle. It is capped at
	// MaxConns.
	MinConns int
}

// DefaultPoolOptions suits one server instance on a database with the usual
// 100 connections.
func DefaultPoolOptions() PoolOptions { return PoolOptions{MaxConns: 20, MinConns: 2} }

// ConnectPool opens a pgx pool with the default sizes.
func ConnectPool(ctx context.Context, databaseURL string) (*pgxpool.Pool, error) {
	return ConnectPoolWithOptions(ctx, databaseURL, DefaultPoolOptions())
}

// ConnectPoolWithOptions opens a pgx pool for the given database URL.
func ConnectPoolWithOptions(ctx context.Context, databaseURL string, opts PoolOptions) (*pgxpool.Pool, error) {
	cfg, err := poolConfig(databaseURL, opts)
	if err != nil {
		return nil, err
	}

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("create pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping db: %w", err)
	}

	return pool, nil
}

func poolConfig(databaseURL string, opts PoolOptions) (*pgxpool.Config, error) {
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse pool config: %w", err)
	}

	maxConns, minConns := opts.MaxConns, opts.MinConns
	if maxConns < 1 {
		maxConns = DefaultPoolOptions().MaxConns
	}
	minConns = max(0, min(minConns, maxConns))
	cfg.MaxConns = clampInt32(maxConns)
	cfg.MinConns = clampInt32(minConns)
	cfg.MaxConnLifetime = 30 * time.Minute
	cfg.MaxConnIdleTime = 5 * time.Minute

	return cfg, nil
}

// clampInt32 narrows to the driver's int32, saturating instead of wrapping.
func clampInt32(n int) int32 {
	if n > math.MaxInt32 {
		return math.MaxInt32
	}
	return int32(n)
}
