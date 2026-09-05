package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/xMinhx/specht/internal/client"
	"github.com/xMinhx/specht/internal/config"
	"github.com/xMinhx/specht/internal/db"
	"github.com/xMinhx/specht/internal/port"
	"github.com/xMinhx/specht/internal/repo"
	"github.com/xMinhx/specht/internal/watcher"
)

type cmd int

const (
	cmdHelp cmd = iota
	cmdProjectsList
	cmdProjectsGet
	cmdFindingsList
	cmdFindingsGet
	cmdFindingsReachability
	cmdGateCheck
	cmdStats
	cmdWatcherBackfill
	cmdWatcherStatus
)

type command struct {
	cmd       cmd
	project   string
	slug      string
	findingID string
	severity  string
	status    string
	state     string
	evidence  string
	limit     int
	since     string
	dryRun    bool
}

func parseArgs(args []string) (command, error) {
	if len(args) < 2 {
		return command{cmd: cmdHelp}, nil
	}

	rest := args[1:]

	if len(rest) == 0 {
		return command{cmd: cmdHelp}, nil
	}

	switch rest[0] {
	case "projects":
		if len(rest) < 2 {
			return command{}, fmt.Errorf("missing subcommand for projects")
		}
		switch rest[1] {
		case "list":
			return command{cmd: cmdProjectsList}, nil
		case "get":
			if len(rest) < 3 {
				return command{}, fmt.Errorf("missing project slug")
			}
			return command{cmd: cmdProjectsGet, slug: rest[2]}, nil
		default:
			return command{}, fmt.Errorf("unknown projects subcommand: %s", rest[1])
		}

	case "findings":
		if len(rest) < 2 {
			return command{}, fmt.Errorf("missing subcommand for findings")
		}
		switch rest[1] {
		case "list":
			c := command{cmd: cmdFindingsList}
			for i := 2; i < len(rest); i++ {
				switch {
				case rest[i] == "--project" && i+1 < len(rest):
					c.project = rest[i+1]
					i++
				case rest[i] == "--severity" && i+1 < len(rest):
					c.severity = rest[i+1]
					i++
				case rest[i] == "--status" && i+1 < len(rest):
					c.status = rest[i+1]
					i++
				case rest[i] == "--limit" && i+1 < len(rest):
					n, err := strconv.Atoi(rest[i+1])
					if err == nil {
						c.limit = n
					}
					i++
				}
			}
			if c.project == "" {
				return command{}, fmt.Errorf("--project is required for findings list")
			}
			return c, nil
		case "get":
			if len(rest) < 3 {
				return command{}, fmt.Errorf("missing finding ID")
			}
			return command{cmd: cmdFindingsGet, findingID: rest[2]}, nil
		case "reachability":
			c := command{cmd: cmdFindingsReachability}
			for i := 2; i < len(rest); i++ {
				switch {
				case rest[i] == "--finding" && i+1 < len(rest):
					c.findingID = rest[i+1]
					i++
				case rest[i] == "--state" && i+1 < len(rest):
					c.state = rest[i+1]
					i++
				case rest[i] == "--evidence" && i+1 < len(rest):
					c.evidence = rest[i+1]
					i++
				}
			}
			if c.findingID == "" {
				return command{}, fmt.Errorf("--finding is required for findings reachability")
			}
			return c, nil
		default:
			return command{}, fmt.Errorf("unknown findings subcommand: %s", rest[1])
		}

	case "stats":
		if len(rest) < 2 {
			return command{}, fmt.Errorf("missing subcommand for stats")
		}
		if rest[1] == "show" && len(rest) >= 3 {
			return command{cmd: cmdStats, slug: rest[2]}, nil
		}
		return command{}, fmt.Errorf("unknown stats subcommand: %s", rest[1])

	case "gate":
		if len(rest) < 2 {
			return command{}, fmt.Errorf("missing subcommand for gate")
		}
		switch rest[1] {
		case "check":
			c := command{cmd: cmdGateCheck}
			for i := 2; i < len(rest); i++ {
				switch {
				case rest[i] == "--project" && i+1 < len(rest):
					c.project = rest[i+1]
					i++
				case rest[i] == "--severity" && i+1 < len(rest):
					c.severity = rest[i+1]
					i++
				}
			}
			if c.project == "" {
				return command{}, fmt.Errorf("--project is required for gate check")
			}
			return c, nil
		default:
			return command{}, fmt.Errorf("unknown gate subcommand: %s", rest[1])
		}

	case "help":
		return command{cmd: cmdHelp}, nil

	case "watcher":
		if len(rest) < 2 {
			return command{}, fmt.Errorf("missing subcommand for watcher")
		}
		switch rest[1] {
		case "backfill":
			c := command{cmd: cmdWatcherBackfill}
			for i := 2; i < len(rest); i++ {
				switch {
				case rest[i] == "--since" && i+1 < len(rest):
					c.since = rest[i+1]
					i++
				case rest[i] == "--dry-run":
					c.dryRun = true
				}
			}
			return c, nil
		case "status":
			return command{cmd: cmdWatcherStatus}, nil
		default:
			return command{}, fmt.Errorf("unknown watcher subcommand: %s", rest[1])
		}

	default:
		return command{}, fmt.Errorf("unknown command: %s", rest[0])
	}
}

func run(cl *client.Client, cmd command) error {
	switch cmd.cmd {
	case cmdHelp:
		printHelp()
		return nil

	case cmdProjectsList:
		projects, err := cl.ListProjects()
		if err != nil {
			return err
		}
		if len(projects) == 0 {
			fmt.Println("No projects found.")
			return nil
		}
		for _, p := range projects {
			desc := ""
			if p.Description != nil {
				desc = *p.Description
			}
			fmt.Printf("%s\t%s\t%s\n", p.Slug, p.Name, desc)
		}
		return nil

	case cmdProjectsGet:
		p, err := cl.GetProject(cmd.slug)
		if err != nil {
			return err
		}
		desc := ""
		if p.Description != nil {
			desc = *p.Description
		}
		fmt.Printf("Slug:       %s\nName:       %s\nDescription: %s\n", p.Slug, p.Name, desc)
		return nil

	case cmdFindingsList:
		var severities []string
		if cmd.severity != "" {
			severities = strings.Split(cmd.severity, ",")
		}
		var statuses []string
		if cmd.status != "" {
			statuses = strings.Split(cmd.status, ",")
		}
		findings, err := cl.ListFindings(cmd.project, severities, statuses, int32(cmd.limit), 0)
		if err != nil {
			return err
		}
		if len(findings) == 0 {
			fmt.Println("No findings found.")
			return nil
		}
		for _, f := range findings {
			score := ""
			if f.CurrentScore != nil {
				score = fmt.Sprintf("%.1f", *f.CurrentScore)
			}
			fmt.Printf("%s\t%s\t%s\t%s\t%s\t%s\n", f.ID, f.CurrentSeverity, f.CurrentTitle, f.AnalysisState, f.GateEffect, score)
		}
		return nil

	case cmdFindingsGet:
		f, err := cl.GetFinding(cmd.findingID)
		if err != nil {
			return err
		}
		score := ""
		if f.CurrentScore != nil {
			score = fmt.Sprintf("%.1f", *f.CurrentScore)
		}
		fmt.Printf("ID:           %s\nTitle:        %s\nSeverity:     %s\nScore:        %s\nState:        %s\nAnalysis:     %s\nGate Effect:  %s\nFingerprint:  %s\nKind:         %s\n", f.ID, f.CurrentTitle, f.CurrentSeverity, score, f.State, f.AnalysisState, f.GateEffect, f.Fingerprint, f.FindingKind)
		return nil

	case cmdFindingsReachability:
		if cmd.state != "" {
			assess, err := cl.UpsertReachability(cmd.findingID, cmd.state, cmd.evidence)
			if err != nil {
				return err
			}
			fmt.Printf("reachability set: finding=%s state=%s evidence=%q\n", assess.FindingID, assess.State, assess.Evidence)
			return nil
		}
		history, err := cl.ListReachability(cmd.findingID)
		if err != nil {
			return err
		}
		if len(history) == 0 {
			fmt.Println("no reachability assessments for finding")
			return nil
		}
		for _, a := range history {
			fmt.Printf("%s\t%s\t%s\t%s\n", a.CreatedAt, a.State, a.AssessedBy, a.Evidence)
		}
		return nil

	case cmdGateCheck:
		gs, err := cl.GetGateStatus(cmd.project, cmd.severity)
		if err != nil {
			return err
		}
		if gs.ThresholdBreached {
			fmt.Printf("gate FAILED: %d blocking finding(s)\n", gs.BlockingCount)
			if len(gs.BlockedBy) > 0 {
				for _, b := range gs.BlockedBy {
					reach := "unknown"
					if r, ok := gs.BlockedByReachability[b]; ok && r != "" {
						reach = r
					}
					fmt.Printf("  blocked by: %s (reachability: %s)\n", b, reach)
				}
			}
			os.Exit(1)
		}
		fmt.Println("gate PASSED: no blocking findings")
		return nil

	case cmdStats:
		stats, err := cl.GetProjectStats(cmd.slug)
		if err != nil {
			return err
		}
		fmt.Printf("Project Stats for %s:\n", cmd.slug)
		fmt.Printf("  Total Findings:  %d\n", stats.TotalFindings)
		fmt.Printf("  Blocking:        %d\n", stats.BlockingCount)
		fmt.Printf("  Active Waivers:  %d\n", stats.WaiverCount)
		fmt.Printf("  Reports:         %d\n", stats.ReportCount)
		fmt.Println("  By Severity:")
		for _, s := range stats.BySeverity {
			fmt.Printf("    %s: %d total, %d blocking\n", s.Severity, s.Count, s.BlockingCount)
		}
		if stats.LatestReport != nil {
			fmt.Printf("  Latest Scan:     %s by %s (%s)\n", stats.LatestReport.ID, stats.LatestReport.ToolName, stats.LatestReport.Status)
		}
		return nil

	case cmdWatcherStatus:
		ws, err := cl.GetWatcherStatus()
		if err != nil {
			return err
		}
		if ws.LastSuccessfulPollAt != "" {
			fmt.Printf("Last Successful Poll:  %s\n", ws.LastSuccessfulPollAt)
		} else {
			fmt.Println("Last Successful Poll:  never (cold start)")
		}
		if ws.LastPollAttemptAt != "" {
			fmt.Printf("Last Poll Attempt:     %s\n", ws.LastPollAttemptAt)
		}
		if ws.LastError != "" {
			fmt.Printf("Last Error:            %s\n", ws.LastError)
		}
		fmt.Printf("Consecutive Failures:  %d\n", ws.ConsecutiveFailures)
		switch {
		case ws.Healthy:
			fmt.Println("Status:                healthy")
		case ws.Stale:
			fmt.Printf("Status:                STALE (no successful poll within %s)\n", ws.StalenessWindow)
		default:
			fmt.Println("Status:                FAILING")
		}
		return nil
	}

	return nil
}

func printHelp() {
	fmt.Print(`Usage: specht <command> [subcommand] [flags]

Commands:
  projects list                           List all projects
  projects get <slug>                     Show project details
  findings list --project <slug>          List findings
    [--severity high,critical]             Filter by severity
    [--status open]                        Filter by status
    [--limit N]                            Limit results
  findings get <id>                       Show finding details
  findings reachability --finding <id>    List reachability assessments (omit --state)
  findings reachability --finding <id> --state <s> [--evidence <e>]
                                          Set reachability (reachable|not_reachable|unknown|not_applicable)
  gate check --project <slug>             Check project gate status
    [--severity critical]                  Severity threshold
  stats show <slug>                       Show project statistics
  watcher backfill [--since <ISO8601>]    Run one CVE watcher poll
  watcher status                          Show watcher health (last poll, failures)
    [--dry-run]                           Report only; write nothing
  help                                     Show this help

Environment:
  API_URL   Specht API base URL (default "http://localhost:8080")
  API_KEY   API key for authentication (required for all commands)
  DATABASE_URL   Postgres connection (required for watcher backfill)
`)
}

func main() {
	cmd, err := parseArgs(os.Args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}

	// The watcher backfill talks to the database and OSV directly; it does
	// not use the API client, so it is dispatched before the API_KEY gate.
	if cmd.cmd == cmdWatcherBackfill {
		if err := runWatcherBackfill(cmd); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(2)
		}
		return
	}

	apiURL := os.Getenv("API_URL")
	if apiURL == "" {
		apiURL = "http://localhost:8080"
	}

	token := os.Getenv("API_KEY")
	if token == "" && cmd.cmd != cmdHelp {
		fmt.Fprintln(os.Stderr, "error: API_KEY environment variable is required")
		os.Exit(2)
	}

	cl := client.New(apiURL, client.WithToken(token))

	if err := run(cl, cmd); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}
}

// runWatcherBackfill runs one CVE watcher poll against the database and OSV,
// using the same PollDeps wiring as the server daemon (cmd/server/main.go).
// It is a one-shot PollOnce: findings for previously unseen advisories are
// persisted (or reported, with --dry-run) and the watermark advances only on
// a fully successful poll.
func runWatcherBackfill(cmd command) error {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		return errors.New("DATABASE_URL is required for watcher backfill")
	}
	ctx := context.Background()
	pool, err := db.ConnectPool(ctx, dbURL)
	if err != nil {
		return fmt.Errorf("connect db: %w", err)
	}
	defer pool.Close()

	stores := repo.NewPortStores(pool)

	var since time.Time
	if cmd.since != "" {
		since, err = time.Parse(time.RFC3339, cmd.since)
		if err != nil {
			return fmt.Errorf("--since must be an ISO8601 timestamp: %w", err)
		}
	}

	var store watcher.PollStore
	if cmd.dryRun {
		store = discardStore{}
	} else {
		store = watcher.NewPollStore(stores)
	}

	projects, err := stores.Projects.List(ctx)
	if err != nil {
		return fmt.Errorf("list projects: %w", err)
	}
	projectIDs := make([]string, len(projects))
	for i, p := range projects {
		projectIDs[i] = p.ID
	}

	inventoryTTL := config.DefaultInventoryTTL
	if v := os.Getenv("INVENTORY_TTL"); v != "" {
		inventoryTTL, err = time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("INVENTORY_TTL is invalid: %w", err)
		}
	}
	watcherCfg, err := config.WatcherConfig()
	if err != nil {
		return err
	}

	deps := watcher.PollDeps{
		Client: watcher.NewHTTPClient(watcher.HTTPClientConfig{
			Endpoint: watcherCfg.OSVEndpoint,
			CacheTTL: 0, // one-shot: no cross-call caching
		}),
		Store:    store,
		Projects: projectIDs,
		Inventory: func(ctx context.Context, projectID string, since time.Duration) ([]port.InventoryPackage, error) {
			return stores.Inventory.DistinctInventory(ctx, projectID, since)
		},
		FindGap: stores.Findings.FindScaFindingIDForPurlAndCve,
		GetWatermark: func(ctx context.Context, projectID string) (time.Time, bool, error) {
			st, err := stores.Watcher.GetProjectState(ctx, projectID)
			if errors.Is(err, port.ErrNotFound) {
				return time.Time{}, false, nil
			}
			if err != nil {
				return time.Time{}, false, err
			}
			if st.LastSuccessfulPollAt == nil {
				return time.Time{}, false, nil
			}
			return *st.LastSuccessfulPollAt, true, nil
		},
		SetWatermark: func(ctx context.Context, projectID string, ts time.Time) error {
			if cmd.dryRun {
				return nil // dry-run writes nothing
			}
			return stores.Watcher.UpsertProjectState(ctx, projectID, ts)
		},
		Logger:       slog.Default(),
		InventoryTTL: inventoryTTL,
		Since:        since, // zero → full history
	}

	outcome, err := watcher.PollOnce(ctx, deps)
	if err != nil {
		return fmt.Errorf("watcher backfill: %w", err)
	}
	fmt.Printf("watcher backfill: projects=%d queried=%d created=%d skipped=%d unchanged=%d ignored=%d orphan_skips=%d\n",
		outcome.Projects, outcome.Queried, outcome.Created, outcome.Skipped, outcome.Unchanged, outcome.Ignored, outcome.OrphanSkips)
	if cmd.dryRun {
		fmt.Println("dry-run: nothing was written")
	}
	return nil
}

// discardStore is the PollStore for --dry-run backfills: it accepts every
// decision without persisting anything, so a dry run writes no findings,
// occurrences, events, or evidence.
type discardStore struct{}

func (discardStore) PersistFoundFinding(ctx context.Context, d watcher.Decision) (string, bool, error) {
	return "", true, nil
}

func (discardStore) PersistSkipEvent(ctx context.Context, suppressingID string, ev watcher.Event) error {
	return nil
}
