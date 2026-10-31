package config

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseLogLevel(t *testing.T) {
	for in, want := range map[string]slog.Level{
		"debug": slog.LevelDebug, "INFO": slog.LevelInfo, "Warn": slog.LevelWarn, "ERROR": slog.LevelError,
	} {
		got, ok := ParseLogLevel(in)
		assert.True(t, ok, in)
		assert.Equal(t, want, got, in)
	}
	for _, in := range []string{"", "verbose", "warning", " warn"} {
		_, ok := ParseLogLevel(in)
		assert.False(t, ok, "%q", in)
	}
}
