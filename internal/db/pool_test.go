package db

import (
	"testing"
	"time"
)

func TestPoolConfig(t *testing.T) {
	cfg, err := poolConfig("postgres://user:pass@localhost:5432/specht", DefaultPoolOptions())
	if err != nil {
		t.Fatalf("poolConfig() error = %v", err)
	}

	if cfg.MaxConns != 20 {
		t.Errorf("MaxConns = %v, want 20", cfg.MaxConns)
	}
	if cfg.MinConns != 2 {
		t.Errorf("MinConns = %v, want 2", cfg.MinConns)
	}
	if cfg.MaxConnLifetime != 30*time.Minute {
		t.Errorf("MaxConnLifetime = %v, want 30m", cfg.MaxConnLifetime)
	}
	if cfg.MaxConnIdleTime != 5*time.Minute {
		t.Errorf("MaxConnIdleTime = %v, want 5m", cfg.MaxConnIdleTime)
	}
}

func TestPoolConfigInvalidURL(t *testing.T) {
	_, err := poolConfig(":not-a-postgres-url", DefaultPoolOptions())
	if err == nil {
		t.Fatal("poolConfig() error = nil, want parse error")
	}
	if got := err.Error(); len(got) < 18 || got[:18] != "parse pool config:" {
		t.Errorf("error = %q, want parse pool config prefix", got)
	}
}

func TestPoolConfigUsesTheGivenSizes(t *testing.T) {
	cfg, err := poolConfig("postgres://user:pass@localhost:5432/specht", PoolOptions{MaxConns: 50, MinConns: 5})
	if err != nil {
		t.Fatalf("poolConfig() error = %v", err)
	}
	if cfg.MaxConns != 50 || cfg.MinConns != 5 {
		t.Errorf("sizes = %d/%d, want 50/5", cfg.MaxConns, cfg.MinConns)
	}
}

func TestPoolConfigNeverKeepsMoreIdleThanItMayOpen(t *testing.T) {
	cfg, err := poolConfig("postgres://user:pass@localhost:5432/specht", PoolOptions{MaxConns: 4, MinConns: 9})
	if err != nil {
		t.Fatalf("poolConfig() error = %v", err)
	}
	if cfg.MinConns != 4 {
		t.Errorf("MinConns = %d, want it capped at MaxConns (4)", cfg.MinConns)
	}
}

func TestPoolConfigAZeroMinimumMeansNoWarmConnections(t *testing.T) {
	cfg, err := poolConfig("postgres://user:pass@localhost:5432/specht", PoolOptions{MaxConns: 10, MinConns: 0})
	if err != nil {
		t.Fatalf("poolConfig() error = %v", err)
	}
	if cfg.MinConns != 0 {
		t.Errorf("MinConns = %d, want 0 when asked for 0", cfg.MinConns)
	}
}

func TestPoolConfigSizesAreClampedToWhatTheDriverCanHold(t *testing.T) {
	cfg, err := poolConfig("postgres://user:pass@localhost:5432/specht", PoolOptions{MaxConns: 1 << 40})
	if err != nil {
		t.Fatalf("poolConfig() error = %v", err)
	}
	if cfg.MaxConns <= 0 {
		t.Errorf("MaxConns = %d, want a positive clamped value", cfg.MaxConns)
	}
}

func TestPoolConfigAZeroOptionsValueStillGivesAWorkingPool(t *testing.T) {
	cfg, err := poolConfig("postgres://user:pass@localhost:5432/specht", PoolOptions{})
	if err != nil {
		t.Fatalf("poolConfig() error = %v", err)
	}
	if cfg.MaxConns != 20 {
		t.Errorf("MaxConns = %d, want the default 20 when none is given", cfg.MaxConns)
	}
}
