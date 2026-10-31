package main

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/config"
)

// A LOG_LEVEL that passes validation is the level the server runs at, in any
// letter case.
func TestSetupLogging_AppliesTheValidatedLevelInAnyCase(t *testing.T) {
	old := slog.Default()
	t.Cleanup(func() { slog.SetDefault(old) })

	cases := []struct {
		level                  string
		debug, info, warn, err bool
	}{
		{"debug", true, true, true, true},
		{"DEBUG", true, true, true, true},
		{"info", false, true, true, true},
		{"Info", false, true, true, true},
		{"warn", false, false, true, true},
		{"WARN", false, false, true, true},
		{"error", false, false, false, true},
		{"Error", false, false, false, true},
	}
	for _, c := range cases {
		t.Run(c.level, func(t *testing.T) {
			cfg := &config.Server{
				DBURL: "postgres://x", LogLevel: c.level, InventoryTTL: 1, SessionMaxAge: 1,
				DBMaxConns: 2, ShutdownTimeout: 1, Intel: config.IntelConfig{TTL: 1},
			}
			require.NoError(t, cfg.Validate())

			setupLogging(cfg.LogLevel)
			ctx := context.Background()
			assert.Equal(t, c.debug, slog.Default().Enabled(ctx, slog.LevelDebug), "debug")
			assert.Equal(t, c.info, slog.Default().Enabled(ctx, slog.LevelInfo), "info")
			assert.Equal(t, c.warn, slog.Default().Enabled(ctx, slog.LevelWarn), "warn")
			assert.Equal(t, c.err, slog.Default().Enabled(ctx, slog.LevelError), "error")
		})
	}
}
