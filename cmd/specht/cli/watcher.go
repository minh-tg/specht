package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/xMinhx/specht/internal/config"
	"github.com/xMinhx/specht/internal/db"
	"github.com/xMinhx/specht/internal/port"
	"github.com/xMinhx/specht/internal/repo"
	"github.com/xMinhx/specht/internal/watcher"
)

// WatcherBackfillOptions controls one direct database/OSV watcher poll.
type WatcherBackfillOptions struct {
	Since  time.Time
	DryRun bool
}

// WatcherBackfillResult is the summary printed by the backfill command.
type WatcherBackfillResult struct {
	Outcome watcher.PollOutcome
}

func newWatcherCmd(d Deps, _ *settings) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "watcher",
		Short: "Inspect and run the CVE watcher",
	}
	cmd.AddCommand(newWatcherBackfillCmd(d), newWatcherStatusCmd(d))
	return cmd
}

func newWatcherStatusCmd(d Deps) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show watcher health",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cl, err := d.NewClient()
			if err != nil {
				return err
			}
			status, err := cl.GetWatcherStatus()
			if err != nil {
				return err
			}
			if status.LastSuccessfulPollAt != "" {
				fmt.Fprintf(d.Out, "Last Successful Poll:  %s\n", status.LastSuccessfulPollAt)
			} else {
				fmt.Fprintln(d.Out, "Last Successful Poll:  never (cold start)")
			}
			if status.LastPollAttemptAt != "" {
				fmt.Fprintf(d.Out, "Last Poll Attempt:     %s\n", status.LastPollAttemptAt)
			}
			if status.LastError != "" {
				fmt.Fprintf(d.Out, "Last Error:            %s\n", status.LastError)
			}
			fmt.Fprintf(d.Out, "Consecutive Failures:  %d\n", status.ConsecutiveFailures)
			switch {
			case status.Healthy:
				fmt.Fprintln(d.Out, "Status:                healthy")
			case status.Stale:
				fmt.Fprintf(d.Out, "Status:                STALE (no successful poll within %s)\n", status.StalenessWindow)
			default:
				fmt.Fprintln(d.Out, "Status:                FAILING")
			}
			return nil
		},
	}
}

func newWatcherBackfillCmd(d Deps) *cobra.Command {
	var since string
	var dryRun bool
	cmd := &cobra.Command{
		Use:   "backfill",
		Short: "Run one CVE watcher poll",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			var parsedSince time.Time
			if since != "" {
				var err error
				parsedSince, err = time.Parse(time.RFC3339, since)
				if err != nil {
					return fmt.Errorf("--since must be an ISO8601 timestamp: %w", err)
				}
			}
			if d.RunWatcherBackfill == nil {
				return errors.New("watcher backfill is not configured")
			}
			result, err := d.RunWatcherBackfill(WatcherBackfillOptions{Since: parsedSince, DryRun: dryRun})
			if err != nil {
				return err
			}
			o := result.Outcome
			fmt.Fprintf(d.Out, "watcher backfill: projects=%d queried=%d created=%d skipped=%d unchanged=%d ignored=%d orphan_skips=%d\n", o.Projects, o.Queried, o.Created, o.Skipped, o.Unchanged, o.Ignored, o.OrphanSkips)
			if dryRun {
				fmt.Fprintln(d.Out, "dry-run: nothing was written")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&since, "since", "", "only include advisories after this ISO8601 timestamp")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "report only; write nothing")
	return cmd
}

func runWatcherBackfill(options WatcherBackfillOptions) (WatcherBackfillResult, error) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		return WatcherBackfillResult{}, errors.New("DATABASE_URL is required for watcher backfill")
	}
	ctx := context.Background()
	pool, err := db.ConnectPool(ctx, dbURL)
	if err != nil {
		return WatcherBackfillResult{}, fmt.Errorf("connect db: %w", err)
	}
	defer pool.Close()

	stores := repo.NewPortStores(pool)
	var store watcher.PollStore
	if options.DryRun {
		store = discardStore{}
	} else {
		store = watcher.NewPollStore(stores)
	}

	projects, err := stores.Projects.List(ctx)
	if err != nil {
		return WatcherBackfillResult{}, fmt.Errorf("list projects: %w", err)
	}
	projectIDs := make([]string, len(projects))
	for i, project := range projects {
		projectIDs[i] = project.ID
	}

	inventoryTTL := config.DefaultInventoryTTL
	if value := os.Getenv("INVENTORY_TTL"); value != "" {
		inventoryTTL, err = time.ParseDuration(value)
		if err != nil {
			return WatcherBackfillResult{}, fmt.Errorf("INVENTORY_TTL is invalid: %w", err)
		}
	}
	watcherConfig, err := config.WatcherConfig()
	if err != nil {
		return WatcherBackfillResult{}, err
	}

	deps := watcher.PollDeps{
		Client: watcher.NewHTTPClient(watcher.HTTPClientConfig{
			Endpoint: watcherConfig.OSVEndpoint,
			CacheTTL: 0,
		}),
		Store:    store,
		Projects: projectIDs,
		Inventory: func(ctx context.Context, projectID string, since time.Duration) ([]port.InventoryPackage, error) {
			return stores.Inventory.DistinctInventory(ctx, projectID, since)
		},
		FindGap: stores.Findings.FindScaFindingIDForPurlAndCve,
		GetWatermark: func(ctx context.Context, projectID string) (time.Time, bool, error) {
			state, err := stores.Watcher.GetProjectState(ctx, projectID)
			if errors.Is(err, port.ErrNotFound) {
				return time.Time{}, false, nil
			}
			if err != nil {
				return time.Time{}, false, err
			}
			if state.LastSuccessfulPollAt == nil {
				return time.Time{}, false, nil
			}
			return *state.LastSuccessfulPollAt, true, nil
		},
		SetWatermark: func(ctx context.Context, projectID string, timestamp time.Time) error {
			if options.DryRun {
				return nil
			}
			return stores.Watcher.UpsertProjectState(ctx, projectID, timestamp)
		},
		Logger:       slog.Default(),
		InventoryTTL: inventoryTTL,
		Since:        options.Since,
	}

	outcome, err := watcher.PollOnce(ctx, deps)
	if err != nil {
		return WatcherBackfillResult{}, fmt.Errorf("watcher backfill: %w", err)
	}
	return WatcherBackfillResult{Outcome: outcome}, nil
}

type discardStore struct{}

func (discardStore) PersistFoundFinding(context.Context, watcher.Decision) (string, bool, error) {
	return "", true, nil
}

func (discardStore) PersistSkipEvent(context.Context, string, watcher.Event) error {
	return nil
}
