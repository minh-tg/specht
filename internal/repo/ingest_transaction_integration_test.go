//go:build integration

package repo

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/parser"
	"github.com/minh-tg/specht/internal/port"
	"github.com/minh-tg/specht/internal/scanner"
	"github.com/minh-tg/specht/internal/tracker"
	"github.com/minh-tg/specht/internal/usecase"
)

type recordedIngestEvents struct{ events []tracker.Event }

func (r *recordedIngestEvents) Dispatch(_ context.Context, event tracker.Event) {
	r.events = append(r.events, event)
}

func transactionalTrivyReport(t *testing.T, severity string) json.RawMessage {
	t.Helper()
	var report map[string]any
	require.NoError(t, json.Unmarshal(syntheticTrivyReport(t, 1), &report))
	result := report["Results"].([]any)[0].(map[string]any)
	if severity == "" {
		result["Vulnerabilities"] = []any{}
	} else {
		result["Vulnerabilities"].([]any)[0].(map[string]any)["Severity"] = severity
	}
	result["Packages"] = []any{map[string]any{"Name": "profile-1-0", "Version": "1.0.0", "Identifier": map[string]any{"PURL": "pkg:npm/profile-1-0@1.0.0"}}}
	raw, err := json.Marshal(report)
	require.NoError(t, err)
	return raw
}

func TestIngestTransactionSerializesOnlyTheSameProject(t *testing.T) {
	pool, cleanup := setupIngestPool(t)
	defer cleanup()
	stores := NewPortStores(pool)
	ctx := context.Background()
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		done <- stores.Ingest.Run(ctx, "project-a", func(*port.Stores) error {
			close(entered)
			<-release
			return nil
		})
	}()
	<-entered
	defer func() { close(release); require.NoError(t, <-done) }()
	waitCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	err := stores.Ingest.Run(waitCtx, "project-a", func(*port.Stores) error {
		t.Error("same-project writer entered before the first transaction ended")
		return nil
	})
	require.Error(t, err)
	otherCtx, cancelOther := context.WithTimeout(ctx, time.Second)
	defer cancelOther()
	require.NoError(t, stores.Ingest.Run(otherCtx, "project-b", func(*port.Stores) error { return nil }))
}

func TestIngestTransactionRollsBackFindingChanges(t *testing.T) {
	for _, mode := range []string{"severity", "reopen", "closure"} {
		t.Run(mode, func(t *testing.T) {
			pool, cleanup := setupIngestPool(t)
			defer cleanup()
			ctx := context.Background()
			stores := NewPortStores(pool)
			project, err := stores.Projects.Create(ctx, port.CreateProjectInput{Slug: "atomic", Name: "Atomic", DeploymentThreshold: "high", Settings: []byte(`{}`)})
			require.NoError(t, err)
			registry := scanner.NewRegistry()
			for _, sc := range parser.Builtins() {
				require.NoError(t, registry.Register(sc))
			}
			events := &recordedIngestEvents{}
			u := usecase.New(usecase.Deps{Stores: stores, Registry: registry, Tracker: events})
			ingest := func(commit, severity string) (*usecase.IngestReportOutput, error) {
				return u.IngestReport(ctx, usecase.IngestReportInput{ProjectSlug: "atomic", Scanner: "trivy", Branch: "main", CommitSha: strings.Repeat(commit, 40), RawData: transactionalTrivyReport(t, severity)})
			}
			_, err = ingest("1", "MEDIUM")
			require.NoError(t, err)
			if mode == "reopen" {
				_, err = ingest("2", "")
				require.NoError(t, err)
			}
			findings, err := stores.Findings.ListByProject(ctx, project.ID, port.ListFindingsParams{Limit: 100})
			require.NoError(t, err)
			require.Len(t, findings, 1)
			before := findings[0]
			beforeScopes, err := stores.Findings.ListScopeSeverities(ctx, []string{before.ID})
			require.NoError(t, err)
			events.events = nil
			var priorEvents int
			require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM finding_events WHERE finding_id=$1`, before.ID).Scan(&priorEvents))
			if mode == "closure" {
				_, err = pool.Exec(ctx, `CREATE FUNCTION reject_completion() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.status='completed' THEN RAISE EXCEPTION 'completion fault'; END IF; RETURN NEW; END $$;
CREATE TRIGGER reject_completion BEFORE UPDATE ON reports FOR EACH ROW EXECUTE FUNCTION reject_completion()`)
			} else {
				_, err = pool.Exec(ctx, `CREATE FUNCTION reject_inventory() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'inventory fault'; END $$;
CREATE TRIGGER reject_inventory BEFORE INSERT ON report_packages FOR EACH ROW EXECUTE FUNCTION reject_inventory()`)
			}
			require.NoError(t, err)
			severity := "CRITICAL"
			if mode == "closure" {
				severity = ""
			}
			_, err = ingest("3", severity)
			require.Error(t, err)
			after, err := stores.Findings.GetByID(ctx, before.ID)
			require.NoError(t, err)
			require.Equal(t, before.State, after.State)
			require.Equal(t, before.CurrentSeverity, after.CurrentSeverity)
			scopes, err := stores.Findings.ListScopeSeverities(ctx, []string{before.ID})
			require.NoError(t, err)
			require.Equal(t, beforeScopes, scopes)
			require.Empty(t, events.events, "rolled-back reports must not dispatch tracker changes")
			var status string
			require.NoError(t, pool.QueryRow(ctx, `SELECT status FROM reports WHERE project_id=$1 AND commit_sha=$2`, project.ID, strings.Repeat("3", 40)).Scan(&status))
			require.Equal(t, "failed", status, "a durable failed report explains the attempt")
			var afterEvents, occurrences int
			require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM finding_events WHERE finding_id=$1`, before.ID).Scan(&afterEvents))
			require.Equal(t, priorEvents, afterEvents)
			require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM finding_occurrences o JOIN reports r ON r.id=o.report_id WHERE r.commit_sha=$1`, strings.Repeat("3", 40)).Scan(&occurrences))
			require.Zero(t, occurrences)
		})
	}
}
