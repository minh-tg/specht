package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDefaults(t *testing.T) {
	t.Setenv("WATCHER_ENABLE", "")
	t.Setenv("INVENTORY_TTL", "")
	t.Setenv("SERVER_ADDR", "")
	t.Setenv("DB_MIGRATE", "")
	t.Setenv("WATCHER_POLL_INTERVAL", "")

	cfg, err := Load()
	assert.NoError(t, err)
	assert.Equal(t, ":8080", cfg.Addr)
	assert.True(t, cfg.DBMigrate, "DB_MIGRATE defaults to true")
	assert.Equal(t, DefaultInventoryTTL, cfg.InventoryTTL)
	assert.False(t, cfg.Watcher.Enable)
	assert.Equal(t, DefaultWatcherPoll, cfg.Watcher.PollInterval)
	assert.Equal(t, DefaultOSVEndpoint, cfg.Watcher.OSVEndpoint)
}

func TestLoad_MalformedWatcherSettingIgnoredWhenDisabled(t *testing.T) {
	t.Setenv("WATCHER_ENABLE", "false")
	t.Setenv("WATCHER_POLL_INTERVAL", "not-a-duration")
	cfg, err := Load()
	assert.NoError(t, err, "malformed optional watcher settings must not fail a disabled watcher")
	assert.False(t, cfg.Watcher.Enable)
}

func TestLoad_MalformedWatcherSettingFailsWhenEnabled(t *testing.T) {
	t.Setenv("WATCHER_ENABLE", "true")
	t.Setenv("WATCHER_POLL_INTERVAL", "not-a-duration")
	_, err := Load()
	assert.ErrorContains(t, err, "WATCHER_POLL_INTERVAL")
}

func TestLoad_InventoryTTLAndAddrOverrides(t *testing.T) {
	t.Setenv("INVENTORY_TTL", "48h")
	t.Setenv("SERVER_ADDR", ":9999")
	t.Setenv("WATCHER_ENABLE", "")
	cfg, err := Load()
	assert.NoError(t, err)
	assert.Equal(t, time.Hour*48, cfg.InventoryTTL)
	assert.Equal(t, ":9999", cfg.Addr)
}

func TestWatcherConfig(t *testing.T) {
	t.Setenv("WATCHER_POLL_INTERVAL", "")
	w, err := WatcherConfig()
	assert.NoError(t, err)
	assert.True(t, w.Enable)
	assert.Equal(t, DefaultOSVEndpoint, w.OSVEndpoint)

	t.Setenv("WATCHER_OSV_ENDPOINT", "https://example.test/querybatch")
	w, err = WatcherConfig()
	assert.NoError(t, err)
	assert.Equal(t, "https://example.test/querybatch", w.OSVEndpoint)
}
