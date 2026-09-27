package db

import (
	"testing"
	"time"
)

func TestPoolConfig(t *testing.T) {
	cfg, err := poolConfig("postgres://user:pass@localhost:5432/specht")
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
	_, err := poolConfig(":not-a-postgres-url")
	if err == nil {
		t.Fatal("poolConfig() error = nil, want parse error")
	}
	if got := err.Error(); len(got) < 18 || got[:18] != "parse pool config:" {
		t.Errorf("error = %q, want parse pool config prefix", got)
	}
}
