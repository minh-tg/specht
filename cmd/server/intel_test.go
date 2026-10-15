package main

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/minh-tg/specht/internal/config"
)

func TestBuildIntelStore(t *testing.T) {
	cfg := config.IntelConfig{Enabled: true, EPSSBaseURL: "https://epss.test", KEVCatalogURL: "https://kev.test", TTL: time.Hour}
	assert.NotNil(t, buildIntelStore(cfg))

	cfg.Enabled = false
	assert.True(t, buildIntelStore(cfg) == nil, "a disabled feed leaves a nil interface, not a typed nil store")
}
