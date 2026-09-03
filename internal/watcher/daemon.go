// ***REMOVED*** PollOnce turns the current
// inventory into OSV querybatch calls and persists or skips findings via an
// injected store; RunCveWatcher drives it on a jittered ticker with backoff.
//
// Everything the poll touches is behind small interfaces or function fields,
// so the whole loop is testable offline with fakes — no database, no network
// (the OSV client already has its own httptest coverage).
package watcher

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/xMinhx/specht/internal/db/sqlc"
)

// PollStore is the persistence surface a poll writes through. The production
// implementation (store.go) persists through repo.FindingRepo unit-of-work
// methods so a created finding lands atomically with its dimensions,
// occurrence, event, and evidence.
type PollStore interface {
	// PersistFoundFinding writes a Decision marked Created: the finding row,
	// its dimensions, the occurrence (report_id NULL for watcher findings),
	// the auto_rule_applied event, and the evidence artifact. It returns the
	// finding id and whether the finding row was actually created. Re-poll
	// hits of an existing watcher finding (same fingerprint) are guarded: no
	// second occurrence is created, and created is false so the poll can
	// count them as unchanged rather than inflated "created".
	PersistFoundFinding(ctx context.Context, d Decision) (pgtype.UUID, bool, error)
	// PersistSkipEvent attaches an auto_rule_skipped event to the
	// scan-derived finding that suppressed a watcher finding (controller
	// ruling: the decision conveys the skip but not the suppressing id, so
	// the wiring resolves it via FindScaFindingIdForPurlAndCve).
	PersistSkipEvent(ctx context.Context, suppressingID pgtype.UUID, ev Event) error
}

// PollDeps are the injectable surfaces PollOnce needs. Function fields keep
// the production wiring trivial (one-line closures over the repo) while tests
// substitute deterministic fakes.
type PollDeps struct {
	// Client is the OSV querybatch client.
	Client Client
	// Store persists decisions.
	Store PollStore
	// Projects is the set of projects to watch. The daemon queries the
	// inventory of every project and attributes findings per project.
	Projects []pgtype.UUID
	// Inventory returns the project's distinct packages seen within the
	// given TTL window (last_seen_at >= now() - since).
	Inventory func(ctx context.Context, projectID pgtype.UUID, since time.Duration) ([]sqlc.DistinctInventoryRow, error)
	// FindGap resolves the scan-derived sca finding that already covers a
	// (name-level purl, candidate ids) pair, or pgx.ErrNoRows when none
	// does. The resolved id is where the auto_rule_skipped event lands.
	FindGap func(ctx context.Context, projectID pgtype.UUID, purlName string, candidateIDs []string) (pgtype.UUID, error)
	// GetWatermark returns the last successful poll timestamp, or
	// (zero, false) when no poll has ever completed (the cold-start
	// condition).
	GetWatermark func(ctx context.Context) (time.Time, bool, error)
	// SetWatermark advances the watermark. The daemon calls it only after a
	// fully successful poll.
	SetWatermark func(ctx context.Context, ts time.Time) error
	// Now supplies the clock for the watermark. Defaults to time.Now.
	Now func() time.Time
	// Logger for poll progress. Defaults to slog.Default().
	Logger *slog.Logger
	// InventoryTTL is the freshness window for distinct inventory queries
	// (INVENTORY_TTL; the daemon converts it to a SQL interval).
	InventoryTTL time.Duration
	// Since is the cold-start lower bound, applied only when no watermark
	// exists. Zero means full history (the default cold start per the
	// design: "everything OSV knows about the inventory, deduped by
	// gap-fill").
	Since time.Time
	// Notifier receives a Slack notification for the findings created
	// during a poll (only decisionCreated outcomes — re-poll hits and
	// skips never notify). It is dispatched asynchronously and never
	// blocks or fails a poll; a nil notifier (or one configured with no
	// webhook URL) disables the channel entirely.
	Notifier Notifier
	// ProjectName resolves a project's display name for notifications.
	// When nil, the project UUID string is used as the name.
	ProjectName func(ctx context.Context, projectID pgtype.UUID) (string, error)
}

// PollOutcome summarizes one poll for logging and tests.
type PollOutcome struct {
	Projects    int // projects queried
	Queried     int // package queries sent to OSV
	Created     int // findings persisted
	Skipped     int // suppressed by a scan-derived finding (event attached)
	Unchanged   int // re-poll hits of existing watcher findings (guard)
	Ignored     int // filtered by cutoff, no affected entry, or unusable input
	OrphanSkips int // skip decisions whose suppressing id was unresolved
}

// PollOnce runs one full poll: every project's inventory is queried against
// OSV, each (advisory, inventory row) pair is decided, and the watermark
// advances only when the entire poll succeeded. Any error aborts the poll and
// leaves the watermark untouched.
func PollOnce(ctx context.Context, deps PollDeps) (PollOutcome, error) {
	if deps.Client == nil {
		return PollOutcome{}, fmt.Errorf("poll deps: client is required")
	}
	if deps.Store == nil {
		return PollOutcome{}, fmt.Errorf("poll deps: store is required")
	}
	if deps.Inventory == nil {
		return PollOutcome{}, fmt.Errorf("poll deps: inventory is required")
	}
	if deps.FindGap == nil {
		return PollOutcome{}, fmt.Errorf("poll deps: find-gap is required")
	}
	if deps.GetWatermark == nil || deps.SetWatermark == nil {
		return PollOutcome{}, fmt.Errorf("poll deps: watermark get/put are required")
	}
	if deps.Now == nil {
		deps.Now = time.Now
	}
	if deps.Logger == nil {
		deps.Logger = slog.Default()
	}

	cutoff, err := pollCutoff(ctx, deps)
	if err != nil {
		return PollOutcome{}, fmt.Errorf("watcher state: %w", err)
	}

	now := deps.Now().UTC()
	outcome := PollOutcome{}
	var created []Decision
	for _, projectID := range deps.Projects {
		outcome.Projects++
		rows, err := deps.Inventory(ctx, projectID, deps.InventoryTTL)
		if err != nil {
			return outcome, fmt.Errorf("inventory for project %s: %w", uuid.UUID(projectID.Bytes), err)
		}
		if len(rows) == 0 {
			continue
		}
		groups := groupInventory(rows)
		queries := make([]Query, len(groups))
		for i, g := range groups {
			queries[i] = Query{Package: QueryPackage{Ecosystem: g.ecosystem, Name: g.name}}
		}
		results, err := deps.Client.QueryBatch(ctx, queries)
		if err != nil {
			return outcome, fmt.Errorf("querybatch for project %s: %w", uuid.UUID(projectID.Bytes), err)
		}
		outcome.Queried += len(queries)
		for i, res := range results {
			g := groups[i]
			for _, advisory := range res.Advisories {
				if !afterCutoff(advisory, cutoff) {
					outcome.Ignored++
					continue
				}
				for _, row := range g.rows {
					kind, skipped, decision, err := decidePair(ctx, deps, g, row, advisory)
					if err != nil {
						return outcome, err
					}
					switch kind {
					case decisionCreated:
						outcome.Created++
						created = append(created, decision)
					case decisionSkipped:
						outcome.Skipped++
					case decisionUnchanged:
						outcome.Unchanged++
					default:
						outcome.Ignored++
						if skipped {
							outcome.OrphanSkips++
						}
					}
				}
			}
		}
	}

	if err := deps.SetWatermark(ctx, now); err != nil {
		return outcome, fmt.Errorf("advance watermark: %w", err)
	}
	notifyCreated(ctx, deps, created)
	deps.Logger.Info("cve watcher poll complete", "projects", outcome.Projects, "queried", outcome.Queried, "created", outcome.Created, "skipped", outcome.Skipped, "unchanged", outcome.Unchanged)
	return outcome, nil
}

// notifyCreated hands the newly created findings to the payload notifier.
// It is deliberately best-effort and non-blocking: notifications are built
// synchronously, then the Notify call is dispatched on a fresh goroutine so a
// slow or dead webhook (which Notify itself swallows after retries) can never
// stall or fail the poll. A nil Notifier is a no-op.
func notifyCreated(ctx context.Context, deps PollDeps, created []Decision) {
	if deps.Notifier == nil || len(created) == 0 {
		return
	}
	notifications := make([]Notification, 0, len(created))
	for _, d := range created {
		project := d.Finding.ProjectID
		if deps.ProjectName != nil {
			if pid, err := uuid.Parse(d.Finding.ProjectID); err == nil {
				if name, err := deps.ProjectName(ctx, pgtype.UUID{Bytes: pid, Valid: true}); err == nil && name != "" {
					project = name
				}
			}
		}
		notifications = append(notifications, NotificationFromDecision(d, project))
	}
	// Copy the context's values; a cancelled parent mid-dispatch only aborts
	// the notifier's own retry sleep, never this return.
	go deps.Notifier.Notify(context.WithoutCancel(ctx), notifications)
}

// pollCutoff resolves the advisory published-date lower bound: the watermark
// on warm polls, the configured cold-start window (or full history) when no
// watermark exists.
func pollCutoff(ctx context.Context, deps PollDeps) (time.Time, error) {
	wm, ok, err := deps.GetWatermark(ctx)
	if err != nil {
		return time.Time{}, err
	}
	if ok {
		return wm, nil
	}
	return deps.Since, nil // zero = full history
}

// afterCutoff reports whether an advisory is eligible given the cutoff. An
// advisory with an unparseable published date is always eligible — a date
// quirk must never hide an advisory.
//
// Known v1 limitation (feed-delta path): the cutoff is keyed on the advisory's
// published date (Published >= watermark on warm polls). Because querybatch is
// NOT a delta feed, an advisory published BEFORE the watermark whose affected
// ranges are later extended or modified is never re-evaluated on warm polls —
// it is filtered here and the modified/added range goes unnoticed. This is the
// documented cost of the watermark+cutoff approach and is tracked on the
// feed-delta upgrade path; do not treat afterCutoff as an incremental-change
// feed.
func afterCutoff(advisory Advisory, cutoff time.Time) bool {
	if cutoff.IsZero() {
		return true
	}
	published, err := time.Parse(time.RFC3339, advisory.Published)
	if err != nil {
		return true
	}
	return !published.Before(cutoff)
}

type decisionKind int

const (
	decisionCreated decisionKind = iota
	decisionSkipped
	decisionUnchanged
	decisionIgnored
)

// decidePair evaluates one (advisory, inventory row) pair and persists the
// outcome. The gap-check closure resolves the suppressing finding id so the
// auto_rule_skipped event can be attached to it. It returns the outcome kind,
// whether the skip was orphaned, and (when created) the decision that carries
// the persisted finding payload for downstream notification.
func decidePair(ctx context.Context, deps PollDeps, g invGroup, row sqlc.DistinctInventoryRow, advisory Advisory) (decisionKind, bool, Decision, error) {
	var suppressing pgtype.UUID
	haveSuppressing := false
	gap := func(ctx context.Context, projectID, purlName string, candidateIDs []string) (bool, error) {
		pid, err := uuid.Parse(projectID)
		if err != nil {
			return false, fmt.Errorf("parse project id %q: %w", projectID, err)
		}
		id, err := deps.FindGap(ctx, pgtype.UUID{Bytes: pid, Valid: true}, purlName, candidateIDs)
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		suppressing, haveSuppressing = id, true
		return true, nil
	}

	input := DecideInput{
		ProjectID: uuid.UUID(row.ProjectID.Bytes).String(),
		Advisory:  advisory,
		Purl:      row.Purl,
		Version:   row.Version.String,
		// Use the grouped OSV-canonical ecosystem (g.ecosystem), not the raw
		// stored row.Ecosystem, so the matcher compares the SAME name the
		// query was sent under. groupInventory maps stored forms to the OSV
		// canonical name (grype stores purl type "golang", OSV returns
		// "Go"); passing the raw stored value here made matchAffected
		// compare "golang" against the advisory's "go" and silently skip
		// every match (whole-branch review, Important finding).
		Ecosystem: g.ecosystem,
	}
	decision, err := DecideFinding(ctx, input, gap)
	if err != nil {
		return decisionIgnored, false, Decision{}, err
	}
	if decision.Created {
		id, created, err := deps.Store.PersistFoundFinding(ctx, decision)
		if err != nil {
			return decisionIgnored, false, Decision{}, err
		}
		_ = id
		if !created {
			// Re-poll hit of an existing watcher finding: the fingerprint is
			// already persisted, so this is an unchanged outcome, not a new
			// finding (re-poll — keep backfill counters honest).
			return decisionUnchanged, false, Decision{}, nil
		}
		return decisionCreated, false, decision, nil
	}
	if decision.Event != nil { // auto_rule_skipped: attach to the suppressing finding
		if haveSuppressing {
			if err := deps.Store.PersistSkipEvent(ctx, suppressing, *decision.Event); err != nil {
				return decisionIgnored, false, Decision{}, err
			}
			return decisionSkipped, false, Decision{}, nil
		}
		return decisionIgnored, true, Decision{}, nil
	}
	return decisionIgnored, false, Decision{}, nil
}

// invGroup is one OSV query key (ecosystem + name) with the inventory rows
// behind it. OSV querybatch is ecosystem-scoped: rows are grouped by the
// OSV-canonical ecosystem so one query covers every version the project has
// seen.
type invGroup struct {
	ecosystem string
	name      string
	rows      []sqlc.DistinctInventoryRow
}

// groupInventory buckets inventory rows by (OSV ecosystem, name), dropping
// rows that cannot be queried (missing ecosystem or name). Group order is
// deterministic so polls are reproducible and the client's result order lines
// up.
func groupInventory(rows []sqlc.DistinctInventoryRow) []invGroup {
	byKey := make(map[string]*invGroup)
	var keys []string
	for _, r := range rows {
		eco := strings.TrimSpace(r.Ecosystem.String)
		name := strings.TrimSpace(r.Name.String)
		if eco == "" || name == "" {
			continue // OSV cannot query a package without an ecosystem or name
		}
		osvEco := OSVEcosystem(eco)
		key := osvEco + "\x00" + name
		g, ok := byKey[key]
		if !ok {
			g = &invGroup{ecosystem: osvEco, name: name}
			byKey[key] = g
			keys = append(keys, key)
		}
		g.rows = append(g.rows, r)
	}
	sort.Strings(keys)
	out := make([]invGroup, len(keys))
	for i, k := range keys {
		out[i] = *byKey[k]
	}
	return out
}

// RunCveWatcherConfig configures the polling loop.
type RunCveWatcherConfig struct {
	// PollDeps feeds each PollOnce call.
	PollDeps PollDeps
	// PollInterval is the steady-state cadence between successful polls.
	// Defaults to 6 hours (design spec default).
	PollInterval time.Duration
	// InitialBackoff is the wait after the first failed poll; it doubles
	// per failure up to MaxBackoff. Defaults to 30 seconds.
	InitialBackoff time.Duration
	// MaxBackoff caps the failure backoff. Defaults to 5 minutes.
	MaxBackoff time.Duration
	// Jitter perturbs any scheduled delay by ±10% to avoid thundering herd
	// against OSV. Defaults to a uniform ±10% jitter over the base delay.
	Jitter func(base time.Duration) time.Duration
	// Sleep blocks for the given delay, returning ctx.Err() early on
	// cancellation. Injectable for deterministic tests; defaults to a
	// cancellable timer.
	Sleep func(ctx context.Context, d time.Duration) error
	// Logger for loop events. Defaults to slog.Default().
	Logger *slog.Logger
}

// RunCveWatcher starts the daemon loop in a background goroutine. The first
// poll fires immediately (design: poll before sleeping), then each iteration
// sleeps the jittered poll interval after a success or the jittered backoff
// after a failure. A single in-process mutex isolates polls: if a poll is
// still running when the next tick fires, the tick is skipped rather than
// overlapped. The loop exits when ctx is done.
func RunCveWatcher(ctx context.Context, cfg RunCveWatcherConfig) {
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 6 * time.Hour
	}
	if cfg.InitialBackoff <= 0 {
		cfg.InitialBackoff = 30 * time.Second
	}
	if cfg.MaxBackoff <= 0 {
		cfg.MaxBackoff = 5 * time.Minute
	}
	if cfg.Jitter == nil {
		cfg.Jitter = jitterDuration
	}
	if cfg.Sleep == nil {
		cfg.Sleep = defaultSleep
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	go func() {
		logger := cfg.Logger
		logger.Info("cve watcher daemon started", "interval", cfg.PollInterval.String())
		var pollMu sync.Mutex
		backoff := time.Duration(0) // first tick is immediate
		for {
			var delay time.Duration
			if !pollMu.TryLock() {
				logger.Warn("cve watcher poll skipped: previous poll still running")
			} else {
				outcome, err := PollOnce(ctx, cfg.PollDeps)
				pollMu.Unlock()
				switch {
				case err != nil:
					backoff = nextBackoff(backoff, cfg.InitialBackoff, cfg.MaxBackoff)
					// Jittered exactly once and reused for both the log and
					// the sleep, so what we report is what we wait (***REMOVED***
					// so what we report is what we wait).
					delay = cfg.Jitter(backoff)
					logger.Error("cve watcher poll failed", "error", err, "next_retry", delay.String())
				default:
					logger.Info("cve watcher poll complete", "projects", outcome.Projects, "queried", outcome.Queried, "created", outcome.Created, "skipped", outcome.Skipped, "unchanged", outcome.Unchanged)
					backoff = 0
					delay = cfg.Jitter(cfg.PollInterval)
				}
			}
			if delay <= 0 {
				// A skipped tick (previous poll still running when the next
				// fired) postpones to the steady-state interval.
				delay = cfg.Jitter(cfg.PollInterval)
			}
			if err := cfg.Sleep(ctx, delay); err != nil {
				logger.Info("cve watcher daemon stopped")
				return
			}
		}
	}()
}

// jitterDuration perturbs a scheduled delay by a uniform ±10% to avoid a
// thundering herd against OSV. A zero or negative base stays zero — a
// degenerate delay must never panic or go negative.
func jitterDuration(base time.Duration) time.Duration {
	if base <= 0 {
		return 0
	}
	factor := 1 + rand.Float64()*0.2 - 0.1
	return time.Duration(float64(base) * factor)
}

// nextBackoff implements the 30s → 5min doubling sequence: the first failure
// waits InitialBackoff, each subsequent failure doubles, capped at MaxBackoff.
func nextBackoff(current, initial, max time.Duration) time.Duration {
	if current <= 0 {
		return initial
	}
	if current >= max {
		return max
	}
	if next := current * 2; next > max {
		return max
	} else {
		return next
	}
}

// defaultSleep sleeps for d or returns ctx.Err() when the context is done
// first.
func defaultSleep(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
