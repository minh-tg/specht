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
	"github.com/minh-tg/specht/internal/sanitize"
	"github.com/minh-tg/specht/internal/version"
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
	introducedOnly  optionalBool
	baseRef         string
	commit          string
	branch          string
	scanMode        string
	scanSeverities  string
	fixableOnly     optionalBool
	baselinePolicy  string
	annotations     bool
	publishCheck    bool
	githubToken     string
	githubRepo      string
	summaryFile     string
	help            bool
	showVersion     bool
	inGitHubActions bool

	// baseFromDefaultBranch is set when detectCIEnvironment filled baseRef from
	// the default branch rather than a flag or a pull request base.
	baseFromDefaultBranch bool
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
	fs.Var(&f.introducedOnly, "introduced-only", "Gate only on findings this change introduced: true or false (default: true when a base ref is set or detected)")
	fs.StringVar(&f.baseRef, "base-ref", "", "Baseline git ref/branch/commit (e.g. main)")
	fs.StringVar(&f.commit, "commit", "", "Current commit SHA")
	fs.StringVar(&f.branch, "branch", "", "Current branch name")
	fs.StringVar(&f.scanMode, "scan-mode", "", "Scan mode: full or incremental")
	fs.StringVar(&f.scanSeverities, "scan-severities", "", "Severities the scan kept, comma-separated, when it was run with a severity filter (trivy: falls back to TRIVY_SEVERITY)")
	fs.Var(&f.fixableOnly, "fixable-only", "The scan kept only findings that have a fix: true or false (trivy: falls back to TRIVY_IGNORE_UNFIXED)")
	fs.StringVar(&f.baselinePolicy, "baseline-policy", "warn", "Missing baseline action: warn or fail (default: warn)")
	fs.BoolVar(&f.annotations, "annotations", inGitHubActions, "Emit GitHub Actions workflow command annotations")
	fs.BoolVar(&f.publishCheck, "publish-check", false, "Publish GitHub check run via API (default: true if GITHUB_TOKEN & GITHUB_REPOSITORY are set in CI)")
	fs.StringVar(&f.githubToken, "github-token", getEnvAny("GITHUB_TOKEN", "GH_TOKEN"), "GitHub token for check-runs API")
	fs.StringVar(&f.githubRepo, "github-repo", os.Getenv("GITHUB_REPOSITORY"), "GitHub repository (owner/repo)")
	fs.StringVar(&f.summaryFile, "summary-file", os.Getenv("GITHUB_STEP_SUMMARY"), "Path to write Markdown summary (e.g. GITHUB_STEP_SUMMARY)")
	fs.BoolVar(&f.help, "help", false, "Show usage")
	fs.BoolVar(&f.showVersion, "version", false, "Print the adapter version and exit")

	if err := fs.Parse(args); err != nil {
		return nil
	}
	return f
}

// writeDiagnostic makes CLI output best-effort; the process exit code carries
// the gate or input-validation result if the writer itself fails.
//
// Every string and error argument is flattened to one line first
// (sanitize.Line). Finding titles, file names, branch names and server error
// messages come from scan output or the network, and the CI runner reads any
// log line that starts with "::" as a workflow command.
func writeDiagnostic(w io.Writer, format string, args ...any) {
	safe := make([]any, len(args))
	for i, arg := range args {
		switch v := arg.(type) {
		case string:
			safe[i] = sanitize.Line(v)
		case error:
			safe[i] = sanitize.Line(v.Error())
		default:
			safe[i] = arg
		}
	}
	_, _ = fmt.Fprint(w, noCommandPrefix(fmt.Sprintf(format, safe...)))
}

// writeDiagnosticLine writes one best-effort CLI diagnostic line.
func writeDiagnosticLine(w io.Writer, message string) {
	_, _ = fmt.Fprintln(w, sanitize.Line(message))
}

// noCommandPrefix keeps a formatted diagnostic that starts with "::" from
// reading as a workflow command.
func noCommandPrefix(s string) string {
	if strings.HasPrefix(s, "::") {
		return " " + s
	}
	return s
}

// readRawInput loads the scan result from the file flag or stdin.
func readRawInput(file string, stdin io.Reader, stderr io.Writer) ([]byte, int) {
	var rawInput []byte
	var err error
	name := "standard input"
	if file != "" {
		name = file
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
	rawInput, err = client.NormalizeScanText(name, rawInput)
	if err != nil {
		writeDiagnostic(stderr, "error: %v\n", err)
		return nil, 2
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
	// The request embeds the scan result as raw JSON, so input that is not
	// JSON or JSON lines could only fail later with an opaque marshal error.
	if !json.Valid(payload.RawData) {
		writeDiagnosticLine(stderr, "error: the scan result is not valid JSON or JSON lines")
		return payload, 2
	}

	applyOwnerEnvironment(&payload, f)
	applyGateFlags(&payload, f)
	applyScanFilter(&payload, f, stderr)
	return payload, 0
}

// applyScanFilter declares on the payload what the scan left out on purpose.
// Trivy and Grype write nothing about --severity or --ignore-unfixed into
// their reports, and the server closes only findings inside the declared
// filter, so a filtered scan has to say so. An explicit flag wins, then a
// filter already in the input envelope, then for trivy its own environment
// variables TRIVY_SEVERITY and TRIVY_IGNORE_UNFIXED. The adapter cannot see
// the flags the scanner ran with, so it prints the filter it declares and
// where each part came from.
func applyScanFilter(payload *client.IngestPayload, f *adapterFlags, stderr io.Writer) {
	var fixable *bool
	if f.fixableOnly.set {
		fixable = &f.fixableOnly.value
	}
	payload.ScanFilter = client.DeclaredScanFilter(payload.Scanner, f.scanSeverities, fixable, payload.ScanFilter, os.Getenv)
	if payload.ScanFilter == nil {
		return
	}
	trivy := strings.EqualFold(payload.Scanner, "trivy")
	severitySource, fixableSource := "the input envelope", "the input envelope"
	switch {
	case f.scanSeverities != "":
		severitySource = "-scan-severities"
	case trivy && os.Getenv("TRIVY_SEVERITY") != "":
		severitySource = "TRIVY_SEVERITY"
	}
	switch {
	case f.fixableOnly.set:
		fixableSource = "-fixable-only"
	case trivy && os.Getenv("TRIVY_IGNORE_UNFIXED") != "":
		fixableSource = "TRIVY_IGNORE_UNFIXED"
	}
	severities := "all (no filter)"
	if len(payload.ScanFilter.Severities) > 0 {
		severities = strings.Join(payload.ScanFilter.Severities, ",") + " (from " + severitySource + ")"
	}
	writeDiagnostic(stderr, "declaring scan filter: severities=%s, fixable_only=%t (from %s); the server closes only findings inside it\n",
		severities, payload.ScanFilter.FixableOnly, fixableSource)
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
	// A base taken from the default branch only sets the comparison point; the
	// gate scope stays project-wide unless -introduced-only asks otherwise.
	payload.GateIntroducedOnly = f.introducedOnly.valueOr(f.baseRef != "" && !f.baseFromDefaultBranch)
}

// optionalBool is a boolean flag that remembers whether it was given, so an
// explicit -introduced-only=false is told apart from an absent flag. A bare
// -introduced-only still means true.
type optionalBool struct {
	set   bool
	value bool
}

func (b *optionalBool) Set(s string) error {
	v, err := strconv.ParseBool(s)
	if err != nil {
		return err
	}
	b.set, b.value = true, v
	return nil
}

func (b *optionalBool) String() string {
	if b == nil || !b.set {
		return ""
	}
	return strconv.FormatBool(b.value)
}

// IsBoolFlag lets the flag package accept the bare form.
func (b *optionalBool) IsBoolFlag() bool { return true }

// valueOr returns the given value, or def when the flag was absent.
func (b optionalBool) valueOr(def bool) bool {
	if b.set {
		return b.value
	}
	return def
}

// publishPreview emits the CI-side outputs (annotations, step summary,
// check run) for a resolved PR check preview.
func publishPreview(ctx context.Context, f *adapterFlags, payload client.IngestPayload, preview *client.PRCheckPreview, apiURL string, stderr io.Writer, hc *http.Client) {
	if preview == nil {
		return
	}
	changeLink := gateChangeURL(apiURL, payload, preview.ReportID, f.severity)
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
// failures. It wraps hc when given, or a fresh client, so retries apply on
// every run. The timeout sits inside the retries and bounds each attempt, with
// the longer ingest timeout for the report upload. A client-wide Timeout would
// instead cover every attempt and backoff together and cut off an ingest the
// server is still allowed to finish.
func newAdapterHTTPClient(hc *http.Client, sleep func(context.Context, time.Duration)) *http.Client {
	if hc == nil {
		hc = &http.Client{}
	} else {
		clone := *hc
		hc = &clone
	}
	hc.Transport = &retryTransport{base: client.NewTimeoutTransport(hc.Transport), sleep: sleep}
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
// context is not retried: shutdown must stay prompt. An attempt that ran out
// its own timeout is not retried either: the server outlived its whole window,
// and a repeated upload would only wait that long again.
func retryableAttempt(req *http.Request, resp *http.Response, err error) bool {
	if err != nil {
		return req.Context().Err() == nil && !errors.Is(err, context.DeadlineExceeded)
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
func printChangeLink(w io.Writer, link string) {
	if link != "" {
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
	// Nothing the adapter prints may carry terminal control sequences from
	// scan output or server messages into the CI log.
	stdout, stderr = sanitize.Writer(stdout), sanitize.Writer(stderr)
	inGitHubActions := os.Getenv("GITHUB_ACTIONS") == "true"
	f := parseFlags(args, stderr, inGitHubActions)
	if f == nil {
		return 2
	}
	if f.help {
		printUsage(stderr)
		return 0
	}
	if f.showVersion {
		_, _ = fmt.Fprintf(stdout, "specht-adapter %s\n", version.String())
		return 0
	}
	if f.status != "" {
		writeDiagnosticLine(stderr, "warning: -status is deprecated and ignored; the project policy decides which finding statuses are gated")
	}
	flagBase := f.baseRef != ""
	detectCIEnvironment(&f.baseRef, &f.commit, &f.branch)
	f.baseFromDefaultBranch = !flagBase && f.baseRef != "" && pullRequestBaseRef() == ""

	apiKey := getEnvAny("API_KEY", "SPECHT_API_KEY")
	if apiKey == "" && isForkPullRequest() {
		skipForkPullRequest(f.summaryFile, stderr)
		return 0
	}
	// A run that names a scanner to exclude may skip without credentials, so
	// the missing-key error waits for the exclusion check. Without the flag it
	// stays first, before any input is read.
	if apiKey == "" && f.excludeTool == "" {
		return failMissingAPIKey(stderr)
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
	if apiKey == "" {
		return failMissingAPIKey(stderr)
	}
	// Resolved after the exclusion check: a skipped scanner talks to no
	// server, so it must not fail on a missing API URL.
	apiURL, code := resolveAPIURL(stderr)
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

// failMissingAPIKey reports the missing credential and returns the runtime
// error exit code.
func failMissingAPIKey(stderr io.Writer) int {
	writeDiagnosticLine(stderr, "error: API_KEY environment variable is required (set API_KEY or SPECHT_API_KEY)")
	return 2
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
	printChangeLink(stdout, gateChangeURL(apiURL, payload, resp.ReportID, f.severity))
	if resp.FallbackReason != "" {
		writeDiagnostic(stderr, "⚠️  BASELINE WARNING: %s\n", resp.FallbackReason)
		if strings.EqualFold(f.baselinePolicy, "fail") {
			writeDiagnosticLine(stderr, "gate FAILED: missing baseline under baseline-policy=fail")
			return 1
		}
	}

	// Resolve the project-wide decision before publishing any check. A preview
	// of introduced findings alone cannot decide a whole-project gate.
	var projectGate *client.GateStatus
	if !payload.GateIntroducedOnly {
		projectGate, err = cl.GetGateStatus(payload.Project, f.severity)
		if err != nil {
			writeDiagnostic(stderr, "error: gate check failed: %v\n", err)
			return 2
		}
	}

	// Fetch introduced annotations for the exact report. In project mode they
	// are explanatory detail, not the check's verdict.
	var preview *client.PRCheckPreview
	if payload.CommitSha != "" {
		preview, err = cl.PreviewPRCheck(payload.Project, payload.CommitSha, "github", resp.ReportID, f.severity)
		if err != nil {
			writeDiagnostic(stderr, "⚠️  could not fetch PR check preview: %v\n", err)
		}
	}
	if preview != nil {
		preview.ReportID = resp.ReportID
		if projectGate != nil {
			applyProjectVerdict(preview, projectGate)
		} else {
			resp.ThresholdBreached = preview.Conclusion == "failure"
		}
	}
	publishPreview(ctx, f, payload, preview, apiURL, stderr, hc)

	if payload.GateIntroducedOnly {
		return reportIntroducedGate(resp, preview, payload, stderr)
	}

	writeDiagnostic(stderr, "report %s ingested, %d finding(s)\n", resp.ReportID, resp.TotalFindings)
	if projectGate.ThresholdBreached {
		writeDiagnostic(stderr, "gate FAILED: %d blocking finding(s)\n", projectGate.BlockingCount)
		return 1
	}
	writeDiagnosticLine(stderr, "gate PASSED: no blocking findings")
	return 0
}

// applyProjectVerdict uses the same decision for publication and process exit.
// Inline annotations remain a subset: the exact report's introduced findings.
func applyProjectVerdict(preview *client.PRCheckPreview, decision *client.GateStatus) {
	preview.Conclusion = "success"
	preview.Title = "Specht: project gate passed"
	if decision.ThresholdBreached {
		preview.Conclusion = "failure"
		preview.Title = fmt.Sprintf("Specht: %d blocking finding(s) in project", decision.BlockingCount)
	} else {
		preview.Annotations = nil
		preview.SummaryCounts = map[string]int{}
	}
	preview.WaivedCount = decision.WaivedCount
	preview.Summary = fmt.Sprintf("Project-wide gate: %s. %d blocking finding(s), including pre-existing debt. Inline annotations cover only findings introduced by this report.\n\n%s",
		preview.Conclusion, decision.BlockingCount, preview.Summary)
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
	if err := client.CheckAPIURL(raw, os.Getenv); err != nil {
		writeDiagnostic(stderr, "error: %v\n", err)
		return "", 2
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

// detectCIEnvironment fills the base ref, commit and branch the flags left
// empty. On a GitHub pull request GITHUB_SHA is the temporary merge commit
// (pull_request) or the base branch tip (pull_request_target), and
// GITHUB_REF_NAME is "N/merge", so the pull request head from the event
// payload comes first. The report, the PR check preview and the check run then
// all name the head commit, the one the pull request lists and required
// checks look at.
func detectCIEnvironment(baseRef, commit, branch *string) {
	if sha, ref, ok := pullRequestHead(); ok {
		if *commit == "" {
			*commit = sha
		}
		if *branch == "" {
			*branch = ref
		}
	}
	if *baseRef == "" {
		*baseRef = pullRequestBaseRef()
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
	// A push build has no pull request base, so it compares against the
	// default branch. This runs last so the built branch is already known.
	if *baseRef == "" {
		*baseRef = defaultBranchBase(*branch)
	}
}

// pullRequestBaseRef returns the target branch of a GitHub pull request or a
// GitLab merge request pipeline, or "" for any other build.
func pullRequestBaseRef() string {
	if v := os.Getenv("GITHUB_BASE_REF"); v != "" {
		return v
	}
	return os.Getenv("CI_MERGE_REQUEST_TARGET_BRANCH_NAME")
}

// defaultBranchBase returns the repository default branch for a branch build
// that is not on the default branch, so the server compares the report with the
// newest full report there. It returns "" for tag builds, builds of the default
// branch itself, and when the default branch is unknown. built is the branch
// the report is for; the result never equals it.
func defaultBranchBase(built string) string {
	def, current := os.Getenv("CI_DEFAULT_BRANCH"), os.Getenv("CI_COMMIT_BRANCH")
	if def == "" {
		def, current = githubDefaultBranch()
	}
	if def == "" || current == "" || current == def || built == def {
		return ""
	}
	return def
}

// githubRepositoryEvent is the slice of a GitHub event payload that names the
// repository default branch.
type githubRepositoryEvent struct {
	Repository struct {
		DefaultBranch string `json:"default_branch"`
	} `json:"repository"`
}

// githubDefaultBranch returns the repository default branch from the event
// payload and the branch being built. Both are "" when the ref is not a branch
// (a tag) or the payload is missing or unreadable; the upload then goes ahead
// without a default-branch base.
func githubDefaultBranch() (def, current string) {
	if os.Getenv("GITHUB_REF_TYPE") == "branch" {
		current = os.Getenv("GITHUB_REF_NAME")
	}
	if ref := os.Getenv("GITHUB_REF"); current == "" && strings.HasPrefix(ref, "refs/heads/") {
		current = strings.TrimPrefix(ref, "refs/heads/")
	}
	if current == "" {
		return "", ""
	}
	raw, err := os.ReadFile(os.Getenv("GITHUB_EVENT_PATH"))
	if err != nil {
		return "", ""
	}
	var event githubRepositoryEvent
	if err := json.Unmarshal(raw, &event); err != nil {
		return "", ""
	}
	return event.Repository.DefaultBranch, current
}

// githubPullRequestEvent is the slice of a GitHub pull_request payload that
// tells a fork apart from an in-repo branch: secrets are never delivered to
// fork jobs, so the adapter must recognize this case before checking the key.
type githubPullRequestEvent struct {
	PullRequest *struct {
		Head struct {
			Sha  string `json:"sha"`
			Ref  string `json:"ref"`
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
	event, ok := readPullRequestEvent()
	if !ok {
		return false
	}
	head := event.PullRequest.Head.Repo
	if head.Fork {
		return true
	}
	base := event.PullRequest.Base.Repo.FullName
	return head.FullName != "" && base != "" && head.FullName != base
}

// readPullRequestEvent decodes GITHUB_EVENT_PATH. It reports false when the
// file is missing, unreadable or carries no pull_request object.
func readPullRequestEvent() (githubPullRequestEvent, bool) {
	var event githubPullRequestEvent
	raw, err := os.ReadFile(os.Getenv("GITHUB_EVENT_PATH"))
	if err != nil {
		return event, false
	}
	if err := json.Unmarshal(raw, &event); err != nil || event.PullRequest == nil {
		return event, false
	}
	return event, true
}

// pullRequestHead returns the head commit and branch on a pull_request or
// pull_request_target event whose payload names a head commit. Any other
// event, or an unreadable payload, reports false and the plain environment
// variables apply.
func pullRequestHead() (sha, ref string, ok bool) {
	switch os.Getenv("GITHUB_EVENT_NAME") {
	case "pull_request", "pull_request_target":
	default:
		return "", "", false
	}
	event, ok := readPullRequestEvent()
	if !ok || event.PullRequest.Head.Sha == "" {
		return "", "", false
	}
	return event.PullRequest.Head.Sha, event.PullRequest.Head.Ref, true
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
  -introduced-only[=bool] Gate only on findings this change introduced. Absent,
                         it is true when a base ref is set or a pull or merge
                         request base is detected and false otherwise;
                         -introduced-only=false gates the whole project even
                         on a pull or merge request
  -base-ref string       Baseline git ref/branch/commit (auto-detected in CI);
                         it sets the baseline, -introduced-only sets the scope.
                         A push build of a non-default branch takes the default
                         branch (GitHub event payload, GitLab CI_DEFAULT_BRANCH)
  -commit string         Current commit SHA (auto-detected in CI)
  -branch string         Current branch name (auto-detected in CI)
  -scan-mode string      Scan mode: full or incremental
  -scan-severities string Severities the scan kept, comma-separated, for a scan run
                         with a severity filter (trivy --severity HIGH,CRITICAL).
                         The server closes only findings inside the filter, so a
                         filtered scan never closes the findings it hid. For
                         -tool=trivy, TRIVY_SEVERITY is used when the flag is absent
  -fixable-only[=bool]   The scan kept only findings that have a fix (trivy
                         --ignore-unfixed, grype --only-fixed). For -tool=trivy,
                         TRIVY_IGNORE_UNFIXED=true is used when the flag is absent
  -baseline-policy string Missing baseline action: warn or fail (default: warn)
  -annotations           Emit GitHub Actions workflow command annotations (default: true in CI)
  -publish-check         Publish GitHub check run via API (requires token and repo)
  -github-token string   GitHub token for check-runs API (auto-detected from GITHUB_TOKEN)
  -github-repo string    GitHub repository (owner/repo) (auto-detected from GITHUB_REPOSITORY)
  -summary-file string   Path to write Markdown summary (auto-detected from GITHUB_STEP_SUMMARY)
  -help                  Show this usage message
  -version               Print the adapter version and exit

Environment:
  API_URL                Specht API base URL (default "http://localhost:8080", alias SPECHT_API_URL)
  API_KEY                API key for authentication (required, alias SPECHT_API_KEY)
  GITHUB_BASE_REF        Auto-detected PR target branch in GitHub Actions
  GITHUB_SHA             Auto-detected commit SHA in GitHub Actions
  GITHUB_EVENT_PATH      On pull_request and pull_request_target events, the
                         pull request head commit and branch from this payload
                         replace GITHUB_SHA and GITHUB_REF_NAME
  GITHUB_REPOSITORY      Auto-detected GitHub repository (owner/repo)
  GITHUB_STEP_SUMMARY    Auto-detected path to Markdown job summary
  GITHUB_TOKEN           Auto-detected GitHub token
  CI_MERGE_REQUEST_TARGET_BRANCH_NAME Auto-detected MR target in GitLab CI
  CI_PROJECT_PATH        Auto-detected GitLab project path for the report owner
  SPECHT_OWNER           Report owner when neither -owner nor the payload sets one
  SPECHT_ENVIRONMENT     Deployment environment when neither -environment nor the payload sets one
  SPECHT_PROJECT         Project slug when neither -project nor the payload sets one
  TRIVY_SEVERITY         With -tool=trivy, the severity filter when -scan-severities is absent
  TRIVY_IGNORE_UNFIXED   With -tool=trivy, true declares a fixable-only scan when -fixable-only is absent

Exit codes:
  0  Pass - no blocking findings, or skipped by -exclude-tool
  1  Fail - blocking findings exist in change scope
  2  Error - API unreachable, invalid input, or configuration error

Examples:
  trivy image --format json myapp:latest | specht-adapter -project=my-app -introduced-only
  specht-adapter -file=scan.json -tool=trivy -project=my-app -base-ref=main
`)
}
