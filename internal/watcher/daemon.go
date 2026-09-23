// Package watcher implements the CVE feed watcher: a daemon that polls the
// current inventory against the OSV API and persists or skips findings via an
// injected store. RunCveWatcher drives the poll loop on a jittered ticker with
// backoff.
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
	// The only use is poll-interval jitter (non-security randomness).
	// nosemgrep: go.lang.security.audit.crypto.math_random.math-random-used
	"math/rand/v2"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/minh-tg/specht/internal/port"
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
	PersistFoundFinding(ctx context.Context, d Decision) (string, bool, error)
	// PersistSkipEvent attaches an auto_rule_skipped event to the
	// scan-derived finding that suppressed a watcher finding (controller
	// ruling: the decision conveys the skip but not the suppressing id, so
	// the wiring resolves it via FindScaFindingIdForPurlAndCve).
	PersistSkipEvent(ctx context.Context, suppressingID string, ev Event) error
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
	Projects []string
	// Inventory returns the project's distinct packages seen within the
	// given TTL window (last_seen_at >= now() - since).
	Inventory func(ctx context.Context, projectID string, since time.Duration) ([]port.InventoryPackage, error)
	// FindGap resolves the scan-derived sca finding that already covers a
	// (name-level purl, candidate ids) pair. An empty id with nil error means
	// no suppressing finding exists. The resolved id is where the
	// auto_rule_skipped event lands.
	FindGap func(ctx context.Context, projectID string, purlName string, candidateIDs []string) (string, error)
	// GetWatermark returns the project's last successful poll timestamp, or
	// (zero, false) when that project has never polled (cold start /
	// catch-up). Per-project so disabling a project cannot lose advisories.
	GetWatermark func(ctx context.Context, projectID string) (time.Time, bool, error)
	// SetWatermark advances a project's watermark. The daemon calls it only
	// after a fully successful poll of that project's inventory.
	SetWatermark func(ctx context.Context, projectID string, ts time.Time) error
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
	// When nil, the project ID string is used as the name.
	ProjectName func(ctx context.Context, projectID string) (string, error)
	// RecordAttempt is an optional health hook called when a poll starts.
	// A nil hook disables attempt recording.
	RecordAttempt func(ctx context.Context, ts time.Time) error
	// RecordFailure is an optional health hook called after a failed poll
	// with the error text. A nil hook disables failure recording.
	RecordFailure func(ctx context.Context, errText string, ts time.Time) error
	// RecordSuccess is an optional health hook called after a successful poll
	// with its completion timestamp. A nil hook disables success recording.
	RecordSuccess func(ctx context.Context, ts time.Time) error
	// ResetFailure is an optional health hook called after a successful
	// poll, clearing the consecutive-failure/error state. A nil hook
	// disables the reset.
	ResetFailure func(ctx context.Context) error
	// WG optionally tracks background goroutines spawned during polling
	// (e.g. asynchronous notification dispatch).
	WG *sync.WaitGroup
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
	if err := validatePollDeps(deps); err != nil {
		return PollOutcome{}, err
	}
	if deps.Now == nil {
		deps.Now = time.Now
	}
	if deps.Logger == nil {
		deps.Logger = slog.Default()
	}
	now := deps.Now().UTC()
	outcome := PollOutcome{}
	var created []Decision
	for _, projectID := range deps.Projects {
		if err := pollProject(ctx, deps, projectID, now, &outcome, &created); err != nil {
			var perr *pollDepsError
			if errors.As(err, &perr) {
				return outcome, fmt.Errorf("%s for project %s: %w", perr.op, projectID, perr.err)
			}
			return outcome, err
		}
	}

	notifyCreated(ctx, deps, created)
	deps.Logger.Info(msgPollComplete, "projects", outcome.Projects, "queried", outcome.Queried, "created", outcome.Created, "skipped", outcome.Skipped, "unchanged", outcome.Unchanged)
	return outcome, nil
}

// pollDepsError tags a per-project failure with the operation that failed
// so PollOnce can add project context once.
type pollDepsError struct {
	op  string
	err error
}

func (e *pollDepsError) Error() string { return e.op + ": " + e.err.Error() }
func (e *pollDepsError) Unwrap() error { return e.err }

func validatePollDeps(deps PollDeps) error {
	switch {
	case deps.Client == nil:
		return fmt.Errorf("poll deps: client is required")
	case deps.Store == nil:
		return fmt.Errorf("poll deps: store is required")
	case deps.Inventory == nil:
		return fmt.Errorf("poll deps: inventory is required")
	case deps.FindGap == nil:
		return fmt.Errorf("poll deps: find-gap is required")
	case deps.GetWatermark == nil || deps.SetWatermark == nil:
		return fmt.Errorf("poll deps: watermark get/put are required")
	}
	return nil
}

// pollProject runs one project's inventory sweep: query OSV for every
// grouped package, decide each (advisory, row) pair, and advance the
// project's watermark only after full success. Failures are wrapped with
// the failing operation for PollOnce to annotate with the project ID.
func pollProject(
	ctx context.Context,
	deps PollDeps,
	projectID string,
	now time.Time,
	outcome *PollOutcome,
	created *[]Decision,
) *pollDepsError {
	outcome.Projects++
	rows, err := deps.Inventory(ctx, projectID, deps.InventoryTTL)
	if err != nil {
		return &pollDepsError{op: "inventory", err: err}
	}
	if len(rows) == 0 {
		return nil
	}
	groups := groupInventory(rows)
	if len(groups) == 0 {
		return nil
	}
	// Per-project cutoff: the project's own last successful poll (or
	// the cold-start bound when it has never polled). A project that
	// was disabled while others advanced does not skip advisories that
	// appeared during its disabled period — its cutoff only reflects
	// its own history.
	cutoff, err := pollCutoff(ctx, deps, projectID)
	if err != nil {
		return &pollDepsError{op: "cutoff", err: err}
	}
	queries := make([]Query, len(groups))
	for i, g := range groups {
		queries[i] = Query{Package: QueryPackage{Ecosystem: g.ecosystem, Name: g.name}}
	}
	results, err := deps.Client.QueryBatch(ctx, queries)
	if err != nil {
		return &pollDepsError{op: "querybatch", err: err}
	}
	outcome.Queried += len(queries)
	for i, res := range results {
		if err := applyAdvisories(ctx, deps, projectID, groups[i], res.Advisories, cutoff, &pollTally{outcome: outcome, created: created}); err != nil {
			return err
		}
	}
	// The project's inventory was polled successfully: advance its own
	// watermark so the next poll uses this as its cutoff. A failure
	// above already returned; reaching here means this project fully
	// succeeded.
	if err := deps.SetWatermark(ctx, projectID, now); err != nil {
		return &pollDepsError{op: "advance watermark", err: err}
	}
	return nil
}

// pollTally carries the mutable counters a project poll accumulates.
type pollTally struct {
	outcome *PollOutcome
	created *[]Decision
}

// applyAdvisories decides every (advisory, inventory row) pair for one
// query result and tallies the outcome counters.
func applyAdvisories(
	ctx context.Context,
	deps PollDeps,
	projectID string,
	group invGroup,
	advisories []Advisory,
	cutoff time.Time,
	tally *pollTally,
) *pollDepsError {
	for _, advisory := range advisories {
		if !afterCutoff(advisory, cutoff) {
			tally.outcome.Ignored++
			continue
		}
		for _, row := range group.rows {
			kind, skipped, decision, err := decidePair(ctx, deps, projectID, group, row, advisory)
			if err != nil {
				return &pollDepsError{op: "decide pair", err: err}
			}
			switch kind {
			case decisionCreated:
				tally.outcome.Created++
				*tally.created = append(*tally.created, decision)
			case decisionSkipped:
				tally.outcome.Skipped++
			case decisionUnchanged:
				tally.outcome.Unchanged++
			default:
				tally.outcome.Ignored++
				if skipped {
					tally.outcome.OrphanSkips++
				}
			}
		}
	}
	return nil
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
			if name, err := deps.ProjectName(ctx, d.Finding.ProjectID); err == nil && name != "" {
				project = name
			}
		}
		notifications = append(notifications, NotificationFromDecision(d, project))
	}
	if deps.WG != nil {
		deps.WG.Add(1)
	}
	// Copy the context's values; a cancelled parent mid-dispatch only aborts
	// the notifier's own retry sleep, never this return.
	go func() {
		if deps.WG != nil {
			defer deps.WG.Done()
		}
		deps.Notifier.Notify(context.WithoutCancel(ctx), notifications)
	}()
}

// pollCutoff resolves one project's advisory published-date lower bound: the
// project's own watermark on warm polls, the configured cold-start window (or
// full history) when that project has never polled.
func pollCutoff(ctx context.Context, deps PollDeps, projectID string) (time.Time, error) {
	wm, ok, err := deps.GetWatermark(ctx, projectID)
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

// Watcher log messages emitted from multiple poll paths.
const (
	msgPollComplete  = "cve watcher poll complete"
	msgDaemonStopped = "cve watcher daemon stopped"
)

// decidePair evaluates one (advisory, inventory row) pair and persists the
// outcome. The gap-check closure resolves the suppressing finding id so the
// auto_rule_skipped event can be attached to it. It returns the outcome kind,
// whether the skip was orphaned, and (when created) the decision that carries
// the persisted finding payload for downstream notification.
// pairGapCheck builds the gap-check callback for one pair, recording the
// suppressing finding id for skip-event attachment.
func pairGapCheck(deps PollDeps, suppressing *string) GapCheck {
	return func(ctx context.Context, gapProjectID, purlName string, candidateIDs []string) (bool, error) {
		id, err := deps.FindGap(ctx, gapProjectID, purlName, candidateIDs)
		if err != nil {
			return false, err
		}
		if id == "" {
			return false, nil
		}
		*suppressing = id
		return true, nil
	}
}

// persistPairDecision writes a decided pair outcome to the store.
func persistPairDecision(ctx context.Context, deps PollDeps, decision Decision, suppressing string) (decisionKind, bool, Decision, error) {
	if decision.Created {
		_, created, err := deps.Store.PersistFoundFinding(ctx, decision)
		if err != nil {
			return decisionIgnored, false, Decision{}, err
		}
		if !created {
			// Re-poll hit of an existing watcher finding: the fingerprint is
			// already persisted, so this is an unchanged outcome, not a new
			// finding — backfill counters must stay honest.
			return decisionUnchanged, false, Decision{}, nil
		}
		return decisionCreated, false, decision, nil
	}
	if decision.Event == nil {
		return decisionIgnored, false, Decision{}, nil
	}
	// auto_rule_skipped: attach to the suppressing finding.
	if suppressing == "" {
		return decisionIgnored, true, Decision{}, nil
	}
	if err := deps.Store.PersistSkipEvent(ctx, suppressing, *decision.Event); err != nil {
		return decisionIgnored, false, Decision{}, err
	}
	return decisionSkipped, false, Decision{}, nil
}

func decidePair(ctx context.Context, deps PollDeps, projectID string, g invGroup, row port.InventoryPackage, advisory Advisory) (decisionKind, bool, Decision, error) {
	var suppressing string
	gap := pairGapCheck(deps, &suppressing)

	input := DecideInput{
		ProjectID: projectID,
		Advisory:  advisory,
		Purl:      row.PURL,
		Version:   row.Version,
		// Use the grouped OSV-canonical ecosystem (g.ecosystem), not the raw
		// stored row.Ecosystem, so the matcher compares the SAME name the
		// query was sent under. groupInventory maps stored forms to the OSV
		// canonical name (grype stores purl type "golang", OSV returns
		// "Go"); passing the raw stored value here made matchAffected
		// compare "golang" against the advisory's "go" and silently skip
		// every matching vulnerability.
		Ecosystem: g.ecosystem,
	}
	decision, err := DecideFinding(ctx, input, gap)
	if err != nil {
		return decisionIgnored, false, Decision{}, err
	}
	return persistPairDecision(ctx, deps, decision, suppressing)
}

// invGroup is one OSV query key (ecosystem + name) with the inventory rows
// behind it. OSV querybatch is ecosystem-scoped: rows are grouped by the
// OSV-canonical ecosystem so one query covers every version the project has
// seen.
type invGroup struct {
	ecosystem string
	name      string
	rows      []port.InventoryPackage
}

// groupInventory buckets inventory rows by (OSV ecosystem, name), dropping
// rows that cannot be queried (missing ecosystem or name). Group order is
// deterministic so polls are reproducible and the client's result order lines
// up.
func groupInventory(rows []port.InventoryPackage) []invGroup {
	byKey := make(map[string]*invGroup)
	var keys []string
	for _, r := range rows {
		eco := strings.TrimSpace(r.Ecosystem)
		name := strings.TrimSpace(r.Name)
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

type RunCveWatcherConfig struct {
	// PollDeps feeds each PollOnce call.
	PollDeps PollDeps
	// PollInterval is the steady-state cadence between successful polls when
	// ProjectIntervals has no entry for a project. Defaults to 6 hours.
	PollInterval time.Duration
	// ProjectIntervals schedules projects independently when non-empty. Each
	// project in PollDeps.Projects uses its mapped interval; missing or invalid
	// entries fall back to PollInterval.
	ProjectIntervals map[string]time.Duration
	// ReloadProjects optionally reloads enabled projects dynamically.
	// When provided, the scheduled watcher re-queries the project list to pick up
	// newly enabled, disabled, or configured projects without restarting the server.
	ReloadProjects func(ctx context.Context) ([]port.Project, error)
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
	// Now supplies the scheduler clock. Defaults to time.Now.
	Now func() time.Time
	// WG optionally tracks background goroutines spawned by the daemon
	// (e.g. asynchronous notification dispatch). Forwarded to PollDeps if
	// PollDeps.WG is nil.
	WG *sync.WaitGroup
}

// RunCveWatcher starts the daemon loop in a background goroutine. The first
// poll fires immediately (design: poll before sleeping), then each iteration
// sleeps the jittered poll interval after a success or the jittered backoff
// after a failure. A single in-process mutex isolates polls: if a poll is
// still running when the next tick fires, the tick is skipped rather than
// overlapped. The loop exits when ctx is done.
func RunCveWatcher(ctx context.Context, cfg RunCveWatcherConfig) {
	cfg = watcherDefaults(cfg)

	go func() {
		logger := cfg.Logger
		if len(cfg.ProjectIntervals) > 0 || cfg.ReloadProjects != nil {
			logger.Info("cve watcher daemon started", "projects", len(cfg.PollDeps.Projects), "project_intervals", true)
			runScheduledCveWatcher(ctx, cfg)
			return
		}
		logger.Info("cve watcher daemon started", "interval", cfg.PollInterval.String())
		runIntervalCveWatcher(ctx, cfg)
	}()
}

// watcherDefaults fills zero-valued knobs with their documented defaults.
func watcherDefaults(cfg RunCveWatcherConfig) RunCveWatcherConfig {
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
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.WG != nil && cfg.PollDeps.WG == nil {
		cfg.PollDeps.WG = cfg.WG
	}
	return cfg
}

// runIntervalCveWatcher drives the fixed-interval poll loop with a
// try-lock so a slow poll skips its next tick instead of queueing.
func runIntervalCveWatcher(ctx context.Context, cfg RunCveWatcherConfig) {
	logger := cfg.Logger
	var pollMu sync.Mutex
	backoff := time.Duration(0) // first tick is immediate
	for {
		var delay time.Duration
		if !pollMu.TryLock() {
			logger.Warn("cve watcher poll skipped: previous poll still running")
		} else {
			now := cfg.Now().UTC()
			if cfg.PollDeps.RecordAttempt != nil {
				if err := cfg.PollDeps.RecordAttempt(ctx, now); err != nil {
					logger.Warn("cve watcher record attempt", "error", err)
				}
			}
			outcome, err := PollOnce(ctx, cfg.PollDeps)
			pollMu.Unlock()
			delay, backoff = intervalTickResult(ctx, cfg, outcome, err, now, backoff)
		}
		if delay <= 0 {
			// A skipped tick (previous poll still running when the next
			// fired) postpones to the steady-state interval.
			delay = cfg.Jitter(cfg.PollInterval)
		}
		if err := cfg.Sleep(ctx, delay); err != nil {
			logger.Info(msgDaemonStopped)
			return
		}
	}
}

// intervalTickResult records one poll's health hooks and returns the delay
// to sleep plus the updated backoff state. The delay is jittered exactly
// once and reused for both the log and the sleep, so what we report is what
// we wait.
func intervalTickResult(
	ctx context.Context,
	cfg RunCveWatcherConfig,
	outcome PollOutcome,
	err error,
	now time.Time,
	backoff time.Duration,
) (time.Duration, time.Duration) {
	logger := cfg.Logger
	if err != nil {
		backoff = nextBackoff(backoff, cfg.InitialBackoff, cfg.MaxBackoff)
		delay := cfg.Jitter(backoff)
		logger.Error("cve watcher poll failed", "error", err, "next_retry", delay.String())
		if cfg.PollDeps.RecordFailure != nil {
			if herr := cfg.PollDeps.RecordFailure(ctx, err.Error(), now); herr != nil {
				logger.Warn("cve watcher record failure", "error", herr)
			}
		}
		return delay, backoff
	}
	logger.Info(msgPollComplete, "projects", outcome.Projects, "queried", outcome.Queried, "created", outcome.Created, "skipped", outcome.Skipped, "unchanged", outcome.Unchanged)
	recordPollSuccess(ctx, cfg)
	return cfg.Jitter(cfg.PollInterval), 0
}

// recordPollSuccess runs the success/reset health hooks, logging hook
// failures without failing the poll.
func recordPollSuccess(ctx context.Context, cfg RunCveWatcherConfig) {
	if cfg.PollDeps.RecordSuccess != nil {
		if herr := cfg.PollDeps.RecordSuccess(ctx, cfg.Now().UTC()); herr != nil {
			cfg.Logger.Warn("cve watcher record success", "error", herr)
		}
	}
	if cfg.PollDeps.ResetFailure != nil {
		if herr := cfg.PollDeps.ResetFailure(ctx); herr != nil {
			cfg.Logger.Warn("cve watcher reset failure", "error", herr)
		}
	}
}

func runScheduledCveWatcher(ctx context.Context, cfg RunCveWatcherConfig) {
	intervals, nextDue := initialSchedules(cfg)
	state := &scheduleState{
		intervals:      intervals,
		nextDue:        nextDue,
		backoffs:       make(map[string]time.Duration, len(nextDue)),
		failedProjects: make(map[string]bool, len(nextDue)),
	}
	reload := makeProjectReloader(ctx, cfg, state)

	for {
		reload()

		if len(state.nextDue) == 0 {
			if !sleepIdle(ctx, cfg) {
				return
			}
			continue
		}

		now := cfg.Now().UTC()
		due, earliest := collectDue(now, state.nextDue)
		if len(due) == 0 {
			if !sleepUntil(ctx, cfg, earliest.Sub(now)) {
				return
			}
			continue
		}

		pollAndRecord(ctx, cfg, now, due, state)
	}
}

// scheduleState is the mutable per-project scheduler bookkeeping.
type scheduleState struct {
	intervals      map[string]time.Duration
	nextDue        map[string]time.Time
	backoffs       map[string]time.Duration
	failedProjects map[string]bool
}

// pollAndRecord runs one scheduled poll round for the due set and records
// the matching health hook (attempt, then failure or success).
func pollAndRecord(ctx context.Context, cfg RunCveWatcherConfig, attemptAt time.Time, due []string, state *scheduleState) {
	logger := cfg.Logger
	if cfg.PollDeps.RecordAttempt != nil {
		if err := cfg.PollDeps.RecordAttempt(ctx, attemptAt); err != nil {
			logger.Warn("cve watcher record attempt", "error", err)
		}
	}
	outcome, pollErr := pollDueProjects(ctx, cfg, due, state)

	if pollErr != nil {
		recordPollFailure(ctx, cfg, pollErr, attemptAt)
		return
	}
	if len(state.failedProjects) > 0 {
		return
	}
	logger.Info(msgPollComplete, "projects", outcome.Projects, "queried", outcome.Queried, "created", outcome.Created, "skipped", outcome.Skipped, "unchanged", outcome.Unchanged)
	recordPollSuccess(ctx, cfg)
}

// recordPollFailure runs the failure hook, logging hook errors.
func recordPollFailure(ctx context.Context, cfg RunCveWatcherConfig, pollErr error, attemptAt time.Time) {
	if cfg.PollDeps.RecordFailure == nil {
		return
	}
	if herr := cfg.PollDeps.RecordFailure(ctx, pollErr.Error(), attemptAt); herr != nil {
		cfg.Logger.Warn("cve watcher record failure", "error", herr)
	}
}

// projectInterval resolves one project's effective poll interval, falling
// back to the daemon interval and then to the 6h default.
func projectInterval(cfg RunCveWatcherConfig, override time.Duration) time.Duration {
	if override > 0 {
		return override
	}
	if cfg.PollInterval > 0 {
		return cfg.PollInterval
	}
	return 6 * time.Hour
}

// initialSchedules seeds every configured project as due immediately.
func initialSchedules(cfg RunCveWatcherConfig) (map[string]time.Duration, map[string]time.Time) {
	intervals := make(map[string]time.Duration, len(cfg.PollDeps.Projects))
	nextDue := make(map[string]time.Time, len(cfg.PollDeps.Projects))
	now := cfg.Now().UTC()
	for _, projectID := range cfg.PollDeps.Projects {
		intervals[projectID] = projectInterval(cfg, cfg.ProjectIntervals[projectID])
		nextDue[projectID] = now
	}
	return intervals, nextDue
}

// makeProjectReloader builds the closure that refreshes the active project
// set from the reloader source (nil ReloadProjects is a no-op).
func makeProjectReloader(ctx context.Context, cfg RunCveWatcherConfig, state *scheduleState) func() {
	return func() {
		if cfg.ReloadProjects == nil {
			return
		}
		projs, err := cfg.ReloadProjects(ctx)
		if err != nil {
			cfg.Logger.Warn("cve watcher reload projects", "error", err)
			return
		}
		activeIDs := make(map[string]bool, len(projs))
		curNow := cfg.Now().UTC()
		for _, p := range projs {
			if !p.CveWatcherEnabled {
				continue
			}
			activeIDs[p.ID] = true
			interval := projectInterval(cfg, time.Duration(p.CveWatcherIntervalSecs)*time.Second)
			state.intervals[p.ID] = interval
			if _, exists := state.nextDue[p.ID]; !exists {
				state.nextDue[p.ID] = curNow
			}
		}
		pruneInactive(state, activeIDs)
	}
}

// pruneInactive drops scheduler state for projects no longer active.
func pruneInactive(state *scheduleState, activeIDs map[string]bool) {
	for id := range state.nextDue {
		if activeIDs[id] {
			continue
		}
		delete(state.nextDue, id)
		delete(state.intervals, id)
		delete(state.backoffs, id)
		delete(state.failedProjects, id)
	}
}

// sleepIdle waits the capped idle delay between reloads with no active
// project; it reports false when the daemon should stop.
func sleepIdle(ctx context.Context, cfg RunCveWatcherConfig) bool {
	if cfg.ReloadProjects == nil {
		cfg.Logger.Info(msgDaemonStopped)
		return false
	}
	idleDelay := cfg.PollInterval
	if idleDelay <= 0 || idleDelay > time.Minute {
		idleDelay = time.Minute
	}
	if err := cfg.Sleep(ctx, idleDelay); err != nil {
		cfg.Logger.Info(msgDaemonStopped)
		return false
	}
	return true
}

// sleepUntil waits (jittered) until the earliest due project; it reports
// false when the daemon should stop.
func sleepUntil(ctx context.Context, cfg RunCveWatcherConfig, delay time.Duration) bool {
	if jittered := cfg.Jitter(delay); jittered > 0 {
		delay = jittered
	}
	if err := cfg.Sleep(ctx, delay); err != nil {
		cfg.Logger.Info(msgDaemonStopped)
		return false
	}
	return true
}

// collectDue splits projects into those due at now and the earliest future
// due time, iterating in sorted order for deterministic behavior.
func collectDue(now time.Time, nextDue map[string]time.Time) (due []string, earliest time.Time) {
	due = make([]string, 0, len(nextDue))
	projectIDs := make([]string, 0, len(nextDue))
	for pid := range nextDue {
		projectIDs = append(projectIDs, pid)
	}
	sort.Strings(projectIDs)

	for _, projectID := range projectIDs {
		dueAt := nextDue[projectID]
		if !now.Before(dueAt) {
			due = append(due, projectID)
			continue
		}
		if earliest.IsZero() || dueAt.Before(earliest) {
			earliest = dueAt
		}
	}
	return due, earliest
}

// pollDueProjects polls each due project in isolation: a failed project
// backs off on its own schedule while the others advance. The combined
// outcome and the first error are returned for health recording.
func pollDueProjects(
	ctx context.Context,
	cfg RunCveWatcherConfig,
	due []string,
	state *scheduleState,
) (PollOutcome, error) {
	outcome := PollOutcome{}
	var pollErr error
	for _, projectID := range due {
		pollDeps := cfg.PollDeps
		pollDeps.Projects = []string{projectID}
		projectOutcome, err := PollOnce(ctx, pollDeps)
		outcome.add(projectOutcome)
		if err == nil {
			delete(state.failedProjects, projectID)
			state.backoffs[projectID] = 0
			state.nextDue[projectID] = cfg.Now().UTC().Add(state.intervals[projectID])
			continue
		}
		backoff := nextBackoff(state.backoffs[projectID], cfg.InitialBackoff, cfg.MaxBackoff)
		state.backoffs[projectID] = backoff
		delay := cfg.Jitter(backoff)
		if delay <= 0 {
			delay = backoff
		}
		state.nextDue[projectID] = cfg.Now().UTC().Add(delay)
		state.failedProjects[projectID] = true
		if pollErr == nil {
			pollErr = fmt.Errorf("project %s: %w", projectID, err)
		}
		cfg.Logger.Error("cve watcher poll failed", "project", projectID, "error", err, "next_retry", delay.String())
	}
	return outcome, pollErr
}

func (o *PollOutcome) add(other PollOutcome) {
	o.Projects += other.Projects
	o.Queried += other.Queried
	o.Created += other.Created
	o.Skipped += other.Skipped
	o.Unchanged += other.Unchanged
	o.Ignored += other.Ignored
	o.OrphanSkips += other.OrphanSkips
}

// jitterDuration perturbs a scheduled delay by a uniform ±10% to avoid a
// thundering herd against OSV. A zero or negative base stays zero — a
// degenerate delay must never panic or go negative.
//
// NOTE: math/rand is used here because this is non-security jitter for poll
// scheduling, not for authentication, authorization, token generation, or any
// security boundary. crypto/rand would be the wrong trade-off: it is slower,
// it would block the watcher loop on system entropy, and the resulting
// delay distribution would still be uniform. The security risk is negligible,
// and the performance cost of crypto/rand here would be real.
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
