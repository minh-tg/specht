//go:build integration

package repo

import (
	"context"
	"encoding/json"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/parser"
	"github.com/minh-tg/specht/internal/port"
	"github.com/minh-tg/specht/internal/scanner"
	"github.com/minh-tg/specht/internal/tracker"
	"github.com/minh-tg/specht/internal/usecase"
)

type countingTracker struct {
	mu     sync.Mutex
	events []tracker.Event
}

func (c *countingTracker) Dispatch(_ context.Context, event tracker.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, event)
}

func TestOneDuplicateFindingCreatesOneTrackerEvent(t *testing.T) {
	pool, cleanup := setupIngestPool(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(pool)
	_, err := stores.Projects.Create(ctx, port.CreateProjectInput{Slug: "dup-probe", Name: "Dup Probe", DeploymentThreshold: "high", Settings: []byte(`{}`)})
	require.NoError(t, err)
	registry := scanner.NewRegistry()
	for _, sc := range parser.Builtins() {
		require.NoError(t, registry.Register(sc))
	}
	trackerEvents := &countingTracker{}
	uc := usecase.New(usecase.Deps{Stores: stores, Registry: registry, Tracker: trackerEvents})
	vuln := map[string]any{
		"VulnerabilityID": "CVE-2032-0001", "PkgName": "openssl", "InstalledVersion": "1.0",
		"Severity": "HIGH", "Title": "duplicate", "PkgIdentifier": map[string]string{"PURL": "pkg:apk/alpine/openssl@1.0"},
	}
	raw, err := json.Marshal(map[string]any{
		"SchemaVersion": 2, "ArtifactName": "dup:1", "ArtifactType": "container_image",
		"Results": []map[string]any{{
			"Target": "dup:1 (alpine)", "Class": "os-pkgs", "Type": "alpine",
			"Vulnerabilities": []map[string]any{vuln, vuln},
		}},
	})
	require.NoError(t, err)
	_, err = uc.IngestReport(ctx, usecase.IngestReportInput{ProjectSlug: "dup-probe", Scanner: "trivy", RawData: raw})
	require.NoError(t, err)

	trackerEvents.mu.Lock()
	defer trackerEvents.mu.Unlock()
	created := 0
	for _, event := range trackerEvents.events {
		if event.Type == tracker.EventCreated {
			created++
		}
	}
	require.Equal(t, 1, created, "one finding must create one event")
}
