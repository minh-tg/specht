//go:build integration

package repo

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/port"
	"github.com/minh-tg/specht/internal/scanner"
	"github.com/minh-tg/specht/internal/usecase"
)

// TestPersistWatcherFinding_AssignsFindingIDsInternally pins the watcher
// create contract against the real store: caller-supplied dimensions and
// event carry no finding id (the row does not exist yet) — the transaction
// assigns it. An adapter that parses those ids eagerly breaks every watcher
// creation (the E2E suite proves the whole path; this pins the layer).
func TestPersistWatcherFinding_AssignsFindingIDsInternally(t *testing.T) {
	pool, cleanup := setupIngestPool(t)
	defer cleanup()
	stores := NewPortStores(pool)
	ctx := context.Background()

	creator, err := stores.Users.Create(ctx, "watcher-persist@example.com", nil, nil)
	require.NoError(t, err)
	uc := usecase.New(usecase.Deps{Stores: stores, Registry: scanner.NewRegistry()})
	_, err = uc.CreateProject(globalAdminCtx(creator.ID),
		"Watcher persist", "watcher-persist", "validation", creator.ID)
	require.NoError(t, err)
	project, err := stores.Projects.GetBySlug(ctx, "watcher-persist")
	require.NoError(t, err)

	source := "watcher"
	f, err := stores.Findings.PersistWatcherFinding(ctx, port.PersistWatcherFindingInput{
		Finding: port.Finding{
			ProjectID:           project.ID,
			FindingKind:         "cve_watcher",
			Fingerprint:         "sha256:watcher-persist-fixture",
			CurrentTitle:        "watcher finding",
			CurrentSeverity:     "critical",
			CurrentSeverityRank: 40,
		},
		Dimensions: []port.DimensionInput{
			{Key: "vulnerability_id", Value: "CVE-2026-777", Source: &source},
		},
		Occurrence: port.OccurrenceInput{
			Title:        "watcher finding",
			Severity:     "critical",
			SeverityRank: 40,
			ToolName:     "cve-watcher",
			Display:      []byte("{}"),
			Metadata:     []byte("{}"),
			ObservedAt:   time.Now(),
		},
		Event: &port.FindingEventInput{
			EventType: "auto_rule_applied",
			Changes:   []byte(`{"source":"test"}`),
		},
	})
	require.NoError(t, err, "creation must not choke on absent caller-side ids")

	events, err := stores.Findings.ListEvents(ctx, f.ID, nil, 10, 0)
	require.NoError(t, err)
	require.Len(t, events, 1, "the event lands on the inserted finding")
	require.Equal(t, "auto_rule_applied", events[0].EventType)
	require.Equal(t, f.ID, events[0].FindingID)

	dims, err := stores.Findings.ListDimensions(ctx, f.ID)
	require.NoError(t, err)
	var vulnIDs []string
	for _, d := range dims {
		if d.Key == "vulnerability_id" {
			vulnIDs = append(vulnIDs, d.Value)
		}
	}
	require.Equal(t, []string{"CVE-2026-777"}, vulnIDs,
		"dimensions land on the inserted finding")
}
