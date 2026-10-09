package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/minh-tg/specht/internal/client"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := runWithContext(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr, nil)
	stop()
	os.Exit(code)
}

// adapterFlags holds the parsed command-line flags for one adapter run.
type adapterFlags struct {
	severity        string
	status          string
	project         string
	owner           string
	environment     string
	tool            string
	excludeTool     string
	file            string
	introducedOnly  bool
	baseRef         string
	commit          string
	branch          string
	scanMode        string
	baselinePolicy  string
	annotations     bool
	publishCheck    bool
	githubToken     string
	githubRepo      string
	summaryFile     string
	help            bool
	inGitHubActions bool
}

// parseFlags defines and parses the adapter flag set. It returns nil when
// parsing failed (flag already wrote the error to stderr).
func parseFlags(args []string, stderr io.Writer, inGitHubActions bool) *adapterFlags {
	fs := flag.NewFlagSet("specht-adapter", flag.ContinueOnError)
	fs.SetOutput(stderr)
	f := &adapterFlags{inGitHubActions: inGitHubActions}

	fs.StringVar(&f.severity, "severity", "", "Severity threshold, comma-separated (the project policy decides; a value here can only tighten it)")
	fs.StringVar(&f.status, "status", "", "Deprecated and ignored; the project policy decides")
	fs.StringVar(&f.project, "project", "", "Project slug (overrides stdin)")
	fs.StringVar(&f.owner, "owner", "", "Report owner, e.g. github://owner/repo (overrides stdin; alias SPECHT_OWNER)")
	fs.StringVar(&f.environment, "environment", "", "Deployment environment (overrides stdin; alias SPECHT_ENVIRONMENT)")
	fs.StringVar(&f.tool, "tool", "", "Scanner name (overrides scanner detected in stdin payload)")
	fs.StringVar(&f.excludeTool, "exclude-tool", "", "Skip if scanner matches this name")
	fs.StringVar(&f.file, "file", "", "Path to scan result file (default: read from stdin)")
	fs.BoolVar(&f.introducedOnly, "introduced-only", false, "Gate strictly on introduced vulnerabilities")
	fs.StringVar(&f.baseRef, "base-ref", "", "Baseline git ref/branch/commit (e.g. main)")
	fs.StringVar(&f.commit, "commit", "", "Current commit SHA")
	fs.StringVar(&f.branch, "branch", "", "Current branch name")
	fs.StringVar(&f.scanMode, "scan-mode", "", "Scan mode: full or incremental")
	fs.StringVar(&f.baselinePolicy, "baseline-policy", "warn", "Missing baseline action: warn or fail (default: warn)")
	fs.BoolVar(&f.annotations, "annotations", inGitHubActions, "Emit GitHub Actions workflow command annotations")
	fs.BoolVar(&f.publishCheck, "publish-check", false, "Publish GitHub check run via API (default: true if GITHUB_TOKEN & GITHUB_REPOSITORY are set in CI)")
	fs.StringVar(&f.githubToken, "github-token", getEnvAny("GITHUB_TOKEN", "GH_TOKEN"), "GitHub token for check-runs API")
	fs.StringVar(&f.githubRepo, "github-repo", os.Getenv("GITHUB_REPOSITORY"), "GitHub repository (owner/repo)")
	fs.StringVar(&f.summaryFile, "summary-file", os.Getenv("GITHUB_STEP_SUMMARY"), "Path to write Markdown summary (e.g. GITHUB_STEP_SUMMARY)")
	fs.BoolVar(&f.help, "help", false, "Show usage")

	if err := fs.Parse(args); err != nil {
		return nil
	}
	return f
}

// writeDiagnostic makes CLI output best-effort; the process exit code carries
// the gate or input-validation result if the writer itself fails.
func writeDiagnostic(w io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(w, format, args...)
}

// writeDiagnosticLine writes one best-effort CLI diagnostic line.
func writeDiagnosticLine(w io.Writer, message string) {
	_, _ = fmt.Fprintln(w, message)
}

// readRawInput loads the scan result from the file flag or stdin.
func readRawInput(file string, stdin io.Reader, stderr io.Writer) ([]byte, int) {
	var rawInput []byte
	var err error
	if file != "" {
		rawInput, err = os.ReadFile(file)
		if err != nil {
			writeDiagnostic(stderr, "error: reading file %q: %v\n", file, err)
			return nil, 2
		}
	} else {
		rawInput, err = io.ReadAll(stdin)
		if err != nil {
			writeDiagnostic(stderr, "error: reading stdin: %v\n", err)
			return nil, 2
		}
	}
	if len(bytes.TrimSpace(rawInput)) == 0 {
		writeDiagnostic(stderr, "error: input is empty, provide a scan result file or pipe to stdin\n")
		return nil, 2
	}
	return rawInput, 0
}

// buildPayload decodes the raw input and layers flag/env overrides on top.
// A non-zero code means the caller should exit (2 = validation failure
// already printed on stderr; 1 = skipped by -exclude-tool).
func buildPayload(rawInput []byte, f *adapterFlags, stderr io.Writer) (client.IngestPayload, int) {
	var payload client.IngestPayload
	// Non-envelope input is scanner output; preserve it and let the selected
	// scanner parser report any format error after ingestion.
	_ = json.Unmarshal(rawInput, &payload)
	if len(payload.RawData) == 0 {
		payload.RawData = normalizeRawJSON(rawInput)
	} else if !json.Valid(payload.RawData) {
		payload.RawData = normalizeRawJSON(payload.RawData)
	}

	if f.project != "" {
		payload.Project = f.project
	}
	if payload.Project == "" {
		if p := os.Getenv("SPECHT_PROJECT"); p != "" {
			payload.Project = p
		}
	}
	if f.tool != "" {
		payload.Scanner = f.tool
	}
	if payload.Scanner == "" {
		writeDiagnostic(stderr, "error: scanner is required (use -tool flag or specify in payload)\n")
		return payload, 2
	}
	if f.excludeTool != "" && strings.EqualFold(payload.Scanner, f.excludeTool) {
		writeDiagnostic(stderr, "skipped: scanner %q excluded by -exclude-tool flag\n", payload.Scanner)
		return payload, -1
	}

	applyOwnerEnvironment(&payload, f)
	applyGateFlags(&payload, f)
	return payload, 0
}

// applyOwnerEnvironment fills the repository owner and the deployment
// environment that give a report its target context. An explicit flag wins,
// then a value already in the input envelope, then the SPECHT_OWNER and
// SPECHT_ENVIRONMENT aliases, and last the provider the adapter runs in. The
// order mirrors the existing project and tool layering.
func applyOwnerEnvironment(payload *client.IngestPayload, f *adapterFlags) {
	if f.owner != "" {
		payload.Owner = f.owner
	}
	if payload.Owner == "" {
		if owner := os.Getenv("SPECHT_OWNER"); owner != "" {
			payload.Owner = owner
		}
	}
	if payload.Owner == "" {
		payload.Owner = derivedOwner()
	}

	if f.environment != "" {
		payload.Environment = f.environment
	}
	if payload.Environment == "" {
		if environment := os.Getenv("SPECHT_ENVIRONMENT"); environment != "" {
			payload.Environment = environment
		}
	}
	if payload.Environment == "" && isCI() {
		payload.Environment = "ci"
	}
}

// derivedOwner names the repository or project a report belongs to from the
// variables the CI provider sets, so a direct scanner file keeps the context
// the old envelope carried.
func derivedOwner() string {
	if repo := os.Getenv("GITHUB_REPOSITORY"); repo != "" {
		return "github://" + repo
	}
	if path := os.Getenv("CI_PROJECT_PATH"); path != "" {
		return "gitlab://" + path
	}
	return ""
}

// normalizeRawJSON converts line-delimited JSON (JSONL/NDJSON) into a standard JSON array.
// If raw is already valid JSON or cannot be parsed as a sequence of multiple JSON values,
// the original input is returned unmodified.
func normalizeRawJSON(raw []byte) []byte {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || json.Valid(trimmed) {
		return raw
	}

	dec := json.NewDecoder(bytes.NewReader(trimmed))
	var items []json.RawMessage
	for {
		var item json.RawMessage
		if err := dec.Decode(&item); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return raw
		}
		items = append(items, item)
	}

	if len(items) <= 1 {
		return raw
	}

	var buf bytes.Buffer
	buf.Grow(len(trimmed) + len(items) + 2)
	buf.WriteByte('[')
	for i, it := range items {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.Write(bytes.TrimSpace(it))
	}
	buf.WriteByte(']')

	res := buf.Bytes()
	if json.Valid(res) {
		return res
	}
	return raw
}

// applyGateFlags copies the gate-scope flags onto the payload. The -status
// flag is deliberately not applied: the server ignores it and the project
// policy decides which statuses are gated.
func applyGateFlags(payload *client.IngestPayload, f *adapterFlags) {
	if f.severity != "" {
		payload.GateSeverity = f.severity
	}
	if f.baseRef != "" {
		payload.BaseRevision = f.baseRef
	}
	if f.commit != "" {
		payload.CommitSha = f.commit
	}
	if f.branch != "" {
		payload.Branch = f.branch
	}
	if f.scanMode != "" {
		payload.ScanMode = f.scanMode
	}
	if f.introducedOnly || f.baseRef != "" {
		payload.GateIntroducedOnly = true
	}
}

// publishPreview emits the CI-side outputs (annotations, step summary,
// check run) for a resolved PR check preview.
func publishPreview(ctx context.Context, f *adapterFlags, payload client.IngestPayload, preview *client.PRCheckPreview, apiURL string, stderr io.Writer, hc *http.Client) {
	if preview == nil {
		return
	}
	changeLink := changeURL(apiURL, payload.Project, payload.CommitSha)
	if f.annotations && len(preview.Annotations) > 0 {
		emitGitHubWorkflowAnnotations(stderr, preview.Annotations)
	}
	if f.summaryFile != "" && preview.Summary != "" {
		if err := writeStepSummary(f.summaryFile, withChangeLink(preview.Summary, changeLink)); err != nil {
			writeDiagnostic(stderr, "⚠️  could not write step summary: %v\n", err)
		}
	}
	shouldPublish := f.publishCheck || (f.inGitHubActions && f.githubToken != "" && f.githubRepo != "")
	if shouldPublish && f.githubToken != "" && f.githubRepo != "" {
		if err := publishGitHubCheckRun(ctx, hc, f.githubToken, f.githubRepo, payload.CommitSha, changeLink, preview); err != nil {
			writeDiagnostic(stderr, "⚠️  could not publish github check run: %v\n", err)
		}
	}
}

// isDuplicateReport reports whether ingest failed because the server already
// holds a byte-identical report (409 duplicate_report). The adapter keeps exit
// 2: no verdict is available for this run.
func isDuplicateReport(err error) bool {
	var apiErr *client.Error
	if !errors.As(err, &apiErr) {
		return false
	}
	return apiErr.StatusCode == http.StatusConflict && (apiErr.Code == "duplicate_report" || apiErr.Code == "")
}

// adapterRequestTimeout bounds one API attempt when the caller supplied no
// client. It mirrors the API client's own default so wrapping the client in
// retries does not change the timeout contract.
const adapterRequestTimeout = 60 * time.Second

// retryBackoff holds the wait before each retry. A transient failure is
// retried at most len(retryBackoff) times.
var retryBackoff = []time.Duration{time.Second, 3 * time.Second}

// maxRetryAfter caps how long a 429 response can ask the adapter to wait.
const maxRetryAfter = 30 * time.Second

// adapterSleep waits out the backoff, or returns early when the request
// context ends, so a signal does not leave the adapter sleeping.
var adapterSleep = func(ctx context.Context, d time.Duration) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
	}
}

// newAdapterHTTPClient returns a client whose requests retry transient
// failures. It wraps hc when given, or a client with the adapter request
// timeout, so retries apply on every run.
func newAdapterHTTPClient(hc *http.Client, sleep func(context.Context, time.Duration)) *http.Client {
	if hc == nil {
		hc = &http.Client{Timeout: adapterRequestTimeout}
	} else {
		clone := *hc
		hc = &clone
	}
	base := hc.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	hc.Transport = &retryTransport{base: base, sleep: sleep}
	return hc
}

// retryTransport retries the transient failures of one API request: network
// errors, 502/503/504 and 429. Any other 4xx is returned immediately, so a
// contract or auth error is not retried.
type retryTransport struct {
	base  http.RoundTripper
	sleep func(context.Context, time.Duration)
}

func (t *retryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	for attempt := 0; ; attempt++ {
		resp, err := t.base.RoundTrip(req)
		if !retryableAttempt(req, resp, err) || attempt >= len(retryBackoff) {
			return resp, err
		}
		wait := retryBackoff[attempt]
		if resp != nil && resp.StatusCode == http.StatusTooManyRequests {
			if d := retryAfterDelay(resp.Header.Get("Retry-After")); d > 0 {
				wait = d
			}
		}
		if resp != nil {
			drainAndClose(resp.Body)
		}
		next, ok := replayRequest(req)
		if !ok {
			return resp, err
		}
		t.sleep(req.Context(), wait)
		if err := req.Context().Err(); err != nil {
			return nil, err
		}
		req = next
	}
}

// retryableAttempt reports whether the attempt may be repeated. A canceled
// context is not retried: shutdown must stay prompt.
func retryableAttempt(req *http.Request, resp *http.Response, err error) bool {
	if err != nil {
		return req.Context().Err() == nil
	}
	switch resp.StatusCode {
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

// replayRequest copies req with a fresh body for the next attempt. It reports
// false when a body exists that cannot be regenerated.
func replayRequest(req *http.Request) (*http.Request, bool) {
	next := req.Clone(req.Context())
	if req.Body == nil {
		return next, true
	}
	if req.GetBody == nil {
		return nil, false
	}
	body, err := req.GetBody()
	if err != nil {
		return nil, false
	}
	next.Body = body
	next.ContentLength = req.ContentLength
	return next, true
}

// drainAndClose releases a response that is discarded before a retry.
func drainAndClose(body io.ReadCloser) {
	if body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(body, 4<<10))
	_ = body.Close()
}

// retryAfterDelay parses a Retry-After header (seconds or HTTP date) and caps
// it at maxRetryAfter. It returns 0 when the header is absent or malformed, so
// the caller falls back to the standard backoff.
func retryAfterDelay(value string) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	if seconds, err := strconv.Atoi(value); err == nil {
		if seconds <= 0 {
			return 0
		}
		return min(time.Duration(seconds)*time.Second, maxRetryAfter)
	}
	if when, err := http.ParseTime(value); err == nil {
		delay := time.Until(when)
		if delay <= 0 {
			return 0
		}
		return min(delay, maxRetryAfter)
	}
	return 0
}

// printChangeLink writes the Specht change page URL to stdout so that GitLab
// and local users see it too, not only GitHub step summaries and check runs.
// The report id, when known, tells the change page which report to open. A
// missing project or commit omits the line entirely.
func printChangeLink(w io.Writer, apiURL, project, commit, reportID string) {
	if link := changeURLWithReport(apiURL, project, commit, reportID); link != "" {
		writeDiagnosticLine(w, "View this change in Specht: "+link)
	}
}

// reportIntroducedGate prints the change-scoped verdict and returns its
// exit code (0 pass, 1 breached).
func reportIntroducedGate(resp *client.IngestResponse, preview *client.PRCheckPreview, payload client.IngestPayload, stderr io.Writer) int {
	if !resp.ThresholdBreached {
		writeDiagnostic(stderr, "✅ SPECHT SECURITY GATE: PASSED\n")
		printContextBanner(stderr, payload)
		if resp.PreExistingCount > 0 {
			writeDiagnostic(stderr, "ℹ️  PRE-EXISTING DEBT IN BASELINE: %d findings ignored\n", resp.PreExistingCount)
		}
		return 0
	}

	writeDiagnosticLine(stderr, "❌ SPECHT SECURITY GATE: FAILED")
	printContextBanner(stderr, payload)
	if preview != nil && len(preview.Annotations) > 0 {
		writeDiagnostic(stderr, "\n🚨 NEW BLOCKING FINDINGS INTRODUCED IN THIS CHANGE (%d):\n", len(preview.Annotations))
		for _, a := range preview.Annotations {
			loc := a.File
			if a.StartLine > 0 {
				loc = fmt.Sprintf("%s:%d", a.File, a.StartLine)
			}
			writeDiagnostic(stderr, "  • [%s] %s: %s\n", strings.ToUpper(a.Level), a.Title, loc)
		}
	} else {
		writeDiagnostic(stderr, "\n🚨 NEW BLOCKING FINDINGS INTRODUCED IN THIS CHANGE: %d\n", resp.IntroducedCount)
	}
	if resp.PreExistingCount > 0 {
		writeDiagnostic(stderr, "ℹ️  PRE-EXISTING DEBT IN BASELINE: %d findings ignored for this gate\n", resp.PreExistingCount)
	}
	return 1
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer, hc *http.Client) int {
	return runWithContext(context.Background(), args, stdin, stdout, stderr, hc)
}

func runWithContext(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, hc *http.Client) int {
	inGitHubActions := os.Getenv("GITHUB_ACTIONS") == "true"
	f := parseFlags(args, stderr, inGitHubActions)
	if f == nil {
		return 2
	}
	if f.help {
		printUsage(stderr)
		return 0
	}
	if f.status != "" {
		writeDiagnosticLine(stderr, "warning: -status is deprecated and ignored; the project policy decides which finding statuses are gated")
	}
	detectCIEnvironment(&f.baseRef, &f.commit, &f.branch)

	apiKey := getEnvAny("API_KEY", "SPECHT_API_KEY")
	if apiKey == "" && isForkPullRequest() {
		skipForkPullRequest(f.summaryFile, stderr)
		return 0
	}
	if apiKey == "" {
		writeDiagnosticLine(stderr, "error: API_KEY environment variable is required (set API_KEY or SPECHT_API_KEY)")
		return 2
	}
	apiURL, code := resolveAPIURL(stderr)
	if code != 0 {
		return code
	}

	rawInput, code := readRawInput(f.file, stdin, stderr)
	if code != 0 {
		return code
	}
	payload, code := buildPayload(rawInput, f, stderr)
	if code == -1 {
		return 0 // skipped by -exclude-tool
	}
	if code != 0 {
		return code
	}

	clientOptions := []client.Option{
		client.WithToken(apiKey),
		client.WithHTTPClient(newAdapterHTTPClient(hc, adapterSleep)),
	}
	cl := client.New(apiURL, clientOptions...).WithContext(ctx)
	return runReportWorkflow(ctx, cl, f, payload, apiURL, stdout, stderr, hc)
}

func runReportWorkflow(ctx context.Context, cl *client.Client, f *adapterFlags, payload client.IngestPayload, apiURL string, stdout, stderr io.Writer, hc *http.Client) int {
	resp, err := cl.IngestReport(&payload)
	if err != nil {
		if isDuplicateReport(err) {
			writeDiagnosticLine(stderr, "error: duplicate report: an identical report was already ingested for this project, so no new verdict was produced")
			return 2
		}
		writeDiagnostic(stderr, "error: ingest failed: %v\n", err)
		return 2
	}
	printChangeLink(stdout, apiURL, payload.Project, payload.CommitSha, resp.ReportID)
	if resp.FallbackReason != "" {
		writeDiagnostic(stderr, "⚠️  BASELINE WARNING: %s\n", resp.FallbackReason)
		if strings.EqualFold(f.baselinePolicy, "fail") {
			writeDiagnosticLine(stderr, "gate FAILED: missing baseline under baseline-policy=fail")
			return 1
		}
	}

	// Fetch PR Check Preview for detailed annotations and summary if commit SHA is present.
	var preview *client.PRCheckPreview
	if payload.CommitSha != "" {
		preview, err = cl.PreviewPRCheck(payload.Project, payload.CommitSha, "github", resp.ReportID, f.severity)
		if err != nil {
			writeDiagnostic(stderr, "⚠️  could not fetch PR check preview: %v\n", err)
		}
	}
	publishPreview(ctx, f, payload, preview, apiURL, stderr, hc)

	if payload.GateIntroducedOnly {
		return reportIntroducedGate(resp, preview, payload, stderr)
	}

	writeDiagnostic(stderr, "report %s ingested, %d finding(s)\n", resp.ReportID, resp.TotalFindings)
	gateResp, err := cl.GetGateStatus(payload.Project, f.severity)
	if err != nil {
		writeDiagnostic(stderr, "error: gate check failed: %v\n", err)
		return 2
	}
	if gateResp.ThresholdBreached {
		writeDiagnostic(stderr, "gate FAILED: %d blocking finding(s)\n", gateResp.BlockingCount)
		return 1
	}
	writeDiagnosticLine(stderr, "gate PASSED: no blocking findings")
	return 0
}

// resolveAPIURL returns the Specht base URL. A CI run must configure it: the
// localhost fallback can silently gate against a server that is not there.
// Outside CI the fallback stays, with a one-line notice.
func resolveAPIURL(stderr io.Writer) (string, int) {
	raw := getEnvAny("API_URL", "SPECHT_API_URL")
	if raw == "" {
		if isCI() {
			writeDiagnosticLine(stderr, "error: SPECHT_API_URL is not set; refusing to default to http://localhost:8080 in CI")
			return "", 2
		}
		writeDiagnosticLine(stderr, "notice: SPECHT_API_URL is not set, using http://localhost:8080")
		raw = "http://localhost:8080"
	}
	return strings.TrimRight(raw, "/"), 0
}

// isCI reports whether the adapter runs in a CI system. Both spellings of the
// GitHub and GitLab markers count, because the snippets set them differently.
func isCI() bool {
	return os.Getenv("CI") == "true" || os.Getenv("GITHUB_ACTIONS") != "" || os.Getenv("GITLAB_CI") != ""
}

func printContextBanner(w io.Writer, p client.IngestPayload) {
	writeDiagnostic(w, "Project: %s | Scanner: %s", p.Project, p.Scanner)
	if p.Branch != "" || p.BaseRevision != "" {
		target := p.BaseRevision
		if target == "" {
			target = "baseline"
		}
		src := p.Branch
		if src == "" {
			src = "head"
		}
		writeDiagnostic(w, " | Branch: %s -> %s", src, target)
	}
	writeDiagnosticLine(w, "")
}

func detectCIEnvironment(baseRef, commit, branch *string) {
	if *baseRef == "" {
		if v := os.Getenv("GITHUB_BASE_REF"); v != "" {
			*baseRef = v
		} else if v := os.Getenv("CI_MERGE_REQUEST_TARGET_BRANCH_NAME"); v != "" {
			*baseRef = v
		}
	}
	if *commit == "" {
		if v := os.Getenv("GITHUB_SHA"); v != "" {
			*commit = v
		} else if v := os.Getenv("CI_COMMIT_SHA"); v != "" {
			*commit = v
		}
	}
	if *branch == "" {
		if v := os.Getenv("GITHUB_REF_NAME"); v != "" {
			*branch = v
		} else if v := os.Getenv("CI_COMMIT_REF_NAME"); v != "" {
			*branch = v
		}
	}
}

// githubPullRequestEvent is the slice of a GitHub pull_request payload that
// tells a fork apart from an in-repo branch: secrets are never delivered to
// fork jobs, so the adapter must recognize this case before checking the key.
type githubPullRequestEvent struct {
	PullRequest *struct {
		Head struct {
			Repo struct {
				Fork     bool   `json:"fork"`
				FullName string `json:"full_name"`
			} `json:"repo"`
		} `json:"head"`
		Base struct {
			Repo struct {
				FullName string `json:"full_name"`
			} `json:"repo"`
		} `json:"base"`
	} `json:"pull_request"`
}

// isForkPullRequest reports whether the current GitHub event is a pull_request
// whose head repository is a fork. A missing or unreadable event payload is
// not treated as a fork, so the run keeps failing closed on the missing key.
func isForkPullRequest() bool {
	if os.Getenv("GITHUB_EVENT_NAME") != "pull_request" {
		return false
	}
	raw, err := os.ReadFile(os.Getenv("GITHUB_EVENT_PATH"))
	if err != nil {
		return false
	}
	var event githubPullRequestEvent
	if err := json.Unmarshal(raw, &event); err != nil || event.PullRequest == nil {
		return false
	}
	head := event.PullRequest.Head.Repo
	if head.Fork {
		return true
	}
	base := event.PullRequest.Base.Repo.FullName
	return head.FullName != "" && base != "" && head.FullName != base
}

// skipForkPullRequest explains on stderr and in the job summary that the gate
// did not run because a fork pull request receives no repository secrets.
func skipForkPullRequest(summaryFile string, stderr io.Writer) {
	writeDiagnosticLine(stderr, forkSkipNotice)
	if summaryFile == "" {
		return
	}
	if err := writeStepSummary(summaryFile, forkSkipSummary); err != nil {
		writeDiagnostic(stderr, "⚠️  could not write step summary: %v\n", err)
	}
}

// forkSkipNotice is the one-line stderr notice for a skipped fork run.
const forkSkipNotice = "notice: this pull request is from a fork, so repository secrets such as SPECHT_API_KEY are not available; the Specht gate is skipped"

// forkSkipSummary is the job summary for a skipped fork run.
const forkSkipSummary = "## Specht gate skipped\n\nThis pull request is from a fork, so repository secrets are not available to the job. The Specht security gate did not run."

func getEnvAny(keys ...string) string {
	for _, k := range keys {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}

func printUsage(w io.Writer) {
	writeDiagnostic(w, `Usage: specht-adapter [flags]

CI/CD gate-check adapter for Specht. Reads a scan result from stdin or a file,
ingests it, then evaluates gate status (change-scoped or project-wide) and
exits based on the policy result.

Flags:
  -project string        Project slug (overrides payload)
  -owner string          Report owner, e.g. github://owner/repo (overrides payload; alias SPECHT_OWNER)
  -environment string    Deployment environment (overrides payload; alias SPECHT_ENVIRONMENT)
  -tool string           Scanner name (overrides payload)
  -exclude-tool string   Skip if scanner name matches this value
  -severity string       Severity threshold, comma-separated (the project policy decides; a value here can only tighten it)
  -status string         Deprecated and ignored; the project policy decides
  -file string           Path to scan result file (default: read from stdin)
  -introduced-only       Gate strictly on introduced vulnerabilities
  -base-ref string       Baseline git ref/branch/commit (auto-detected in CI)
  -commit string         Current commit SHA (auto-detected in CI)
  -branch string         Current branch name (auto-detected in CI)
  -scan-mode string      Scan mode: full or incremental
  -baseline-policy string Missing baseline action: warn or fail (default: warn)
  -annotations           Emit GitHub Actions workflow command annotations (default: true in CI)
  -publish-check         Publish GitHub check run via API (requires token and repo)
  -github-token string   GitHub token for check-runs API (auto-detected from GITHUB_TOKEN)
  -github-repo string    GitHub repository (owner/repo) (auto-detected from GITHUB_REPOSITORY)
  -summary-file string   Path to write Markdown summary (auto-detected from GITHUB_STEP_SUMMARY)
  -help                  Show this usage message

Environment:
  API_URL                Specht API base URL (default "http://localhost:8080", alias SPECHT_API_URL)
  API_KEY                API key for authentication (required, alias SPECHT_API_KEY)
  GITHUB_BASE_REF        Auto-detected PR target branch in GitHub Actions
  GITHUB_SHA             Auto-detected commit SHA in GitHub Actions
  GITHUB_REPOSITORY      Auto-detected GitHub repository (owner/repo)
  GITHUB_STEP_SUMMARY    Auto-detected path to Markdown job summary
  GITHUB_TOKEN           Auto-detected GitHub token
  CI_MERGE_REQUEST_TARGET_BRANCH_NAME Auto-detected MR target in GitLab CI
  CI_PROJECT_PATH        Auto-detected GitLab project path for the report owner
  SPECHT_OWNER           Report owner when neither -owner nor the payload sets one
  SPECHT_ENVIRONMENT     Deployment environment when neither -environment nor the payload sets one
  SPECHT_PROJECT         Project slug when neither -project nor the payload sets one

Exit codes:
  0  Pass - no blocking findings, or skipped by -exclude-tool
  1  Fail - blocking findings exist in change scope
  2  Error - API unreachable, invalid input, or configuration error

Examples:
  trivy image --format json myapp:latest | specht-adapter -project=my-app -introduced-only
  specht-adapter -file=scan.json -tool=trivy -project=my-app -base-ref=main
`)
}
