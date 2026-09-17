package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/xMinhx/specht/internal/client"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, nil))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer, hc *http.Client) int {
	fs := flag.NewFlagSet("specht-adapter", flag.ContinueOnError)
	fs.SetOutput(stderr)

	severity := fs.String("severity", "", "Severity threshold (comma-separated, default: high,critical)")
	status := fs.String("status", "", "Finding status filter (default: open)")
	project := fs.String("project", "", "Project slug (overrides stdin)")
	tool := fs.String("tool", "", "Scanner name (overrides scanner detected in stdin payload)")
	excludeTool := fs.String("exclude-tool", "", "Skip if scanner matches this name")
	file := fs.String("file", "", "Path to scan result file (default: read from stdin)")
	introducedOnly := fs.Bool("introduced-only", false, "Gate strictly on introduced vulnerabilities")
	baseRef := fs.String("base-ref", "", "Baseline git ref/branch/commit (e.g. main)")
	commit := fs.String("commit", "", "Current commit SHA")
	branch := fs.String("branch", "", "Current branch name")
	scanMode := fs.String("scan-mode", "", "Scan mode: full or incremental")
	baselinePolicy := fs.String("baseline-policy", "warn", "Missing baseline action: warn or fail (default: warn)")

	// CI & PR Check Publisher flags
	inGitHubActions := os.Getenv("GITHUB_ACTIONS") == "true"
	annotations := fs.Bool("annotations", inGitHubActions, "Emit GitHub Actions workflow command annotations")
	publishCheck := fs.Bool("publish-check", false, "Publish GitHub check run via API (default: true if GITHUB_TOKEN & GITHUB_REPOSITORY are set in CI)")
	githubToken := fs.String("github-token", getEnvAny("GITHUB_TOKEN", "GH_TOKEN"), "GitHub token for check-runs API")
	githubRepo := fs.String("github-repo", os.Getenv("GITHUB_REPOSITORY"), "GitHub repository (owner/repo)")
	summaryFile := fs.String("summary-file", os.Getenv("GITHUB_STEP_SUMMARY"), "Path to write Markdown summary (e.g. GITHUB_STEP_SUMMARY)")
	help := fs.Bool("help", false, "Show usage")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *help {
		printUsage(stderr)
		return 0
	}

	detectCIEnvironment(baseRef, commit, branch)

	apiURL := os.Getenv("API_URL")
	if apiURL == "" {
		apiURL = "http://localhost:8080"
	}
	apiURL = strings.TrimRight(apiURL, "/")

	apiKey := os.Getenv("API_KEY")
	if apiKey == "" {
		fmt.Fprintln(stderr, "error: API_KEY environment variable is required")
		return 2
	}

	var rawInput []byte
	var err error
	if *file != "" {
		rawInput, err = os.ReadFile(*file)
		if err != nil {
			fmt.Fprintf(stderr, "error: reading file %q: %v\n", *file, err)
			return 2
		}
	} else {
		rawInput, err = io.ReadAll(stdin)
		if err != nil {
			fmt.Fprintf(stderr, "error: reading stdin: %v\n", err)
			return 2
		}
	}

	if len(bytes.TrimSpace(rawInput)) == 0 {
		fmt.Fprintln(stderr, "error: input is empty, provide a scan result file or pipe to stdin")
		return 2
	}

	var payload client.IngestPayload
	_ = json.Unmarshal(rawInput, &payload)
	if len(payload.RawData) == 0 {
		payload.RawData = rawInput
	}

	if *project != "" {
		payload.Project = *project
	}
	if payload.Project == "" {
		if p := os.Getenv("SPECHT_PROJECT"); p != "" {
			payload.Project = p
		}
	}

	if *tool != "" {
		payload.Scanner = *tool
	}

	if payload.Scanner == "" {
		fmt.Fprintln(stderr, "error: scanner is required (use -tool flag or specify in payload)")
		return 2
	}

	if *excludeTool != "" && strings.EqualFold(payload.Scanner, *excludeTool) {
		fmt.Fprintf(stderr, "skipped: scanner %q excluded by -exclude-tool flag\n", payload.Scanner)
		return 0
	}

	if *severity != "" {
		payload.GateSeverity = *severity
	}
	if *status != "" {
		payload.GateStatus = *status
	}
	if *baseRef != "" {
		payload.BaseRevision = *baseRef
	}
	if *commit != "" {
		payload.CommitSha = *commit
	}
	if *branch != "" {
		payload.Branch = *branch
	}
	if *scanMode != "" {
		payload.ScanMode = *scanMode
	}

	isIntroducedOnly := *introducedOnly || *baseRef != ""
	if isIntroducedOnly {
		payload.GateIntroducedOnly = true
	}

	opts := []client.Option{client.WithToken(apiKey)}
	if hc != nil {
		opts = append(opts, client.WithHTTPClient(hc))
	}
	cl := client.New(apiURL, opts...)

	resp, err := cl.IngestReport(&payload)
	if err != nil {
		fmt.Fprintf(stderr, "error: ingest failed: %v\n", err)
		return 2
	}

	if resp.FallbackReason != "" {
		fmt.Fprintf(stderr, "⚠️  BASELINE WARNING: %s\n", resp.FallbackReason)
		if strings.EqualFold(*baselinePolicy, "fail") {
			fmt.Fprintln(stderr, "gate FAILED: missing baseline under baseline-policy=fail")
			return 1
		}
	}

	// Fetch PR Check Preview for detailed annotations and summary if commit SHA is present
	var preview *client.PRCheckPreview
	if payload.CommitSha != "" {
		preview, _ = cl.PreviewPRCheck(payload.Project, payload.CommitSha, "github", resp.ReportID, *severity)
	}

	// Emit inline GitHub Actions annotations if enabled
	if *annotations && preview != nil && len(preview.Annotations) > 0 {
		emitGitHubWorkflowAnnotations(stderr, preview.Annotations)
	}

	// Write Markdown Step Summary if target is provided
	if *summaryFile != "" && preview != nil && preview.Summary != "" {
		if err := writeStepSummary(*summaryFile, preview.Summary); err != nil {
			fmt.Fprintf(stderr, "⚠️  could not write step summary: %v\n", err)
		}
	}

	// Publish GitHub Check Run if explicitly requested or auto-configured with token & repo
	shouldPublish := *publishCheck || (inGitHubActions && *githubToken != "" && *githubRepo != "")
	if shouldPublish && *githubToken != "" && *githubRepo != "" && preview != nil {
		if err := publishGitHubCheckRun(context.Background(), hc, *githubToken, *githubRepo, payload.CommitSha, preview); err != nil {
			fmt.Fprintf(stderr, "⚠️  could not publish github check run: %v\n", err)
		}
	}

	if isIntroducedOnly {
		if resp.ThresholdBreached {
			fmt.Fprintln(stderr, "❌ SPECHT SECURITY GATE: FAILED")
			printContextBanner(stderr, payload)
			if preview != nil && len(preview.Annotations) > 0 {
				fmt.Fprintf(stderr, "\n🚨 NEW BLOCKING FINDINGS INTRODUCED IN THIS CHANGE (%d):\n", len(preview.Annotations))
				for _, a := range preview.Annotations {
					loc := a.File
					if a.StartLine > 0 {
						loc = fmt.Sprintf("%s:%d", a.File, a.StartLine)
					}
					fmt.Fprintf(stderr, "  • [%s] %s: %s\n", strings.ToUpper(a.Level), a.Title, loc)
				}
			} else {
				fmt.Fprintf(stderr, "\n🚨 NEW BLOCKING FINDINGS INTRODUCED IN THIS CHANGE: %d\n", resp.IntroducedCount)
			}
			if resp.PreExistingCount > 0 {
				fmt.Fprintf(stderr, "ℹ️  PRE-EXISTING DEBT IN BASELINE: %d findings ignored for this gate\n", resp.PreExistingCount)
			}
			return 1
		}

		fmt.Fprintln(stderr, "✅ SPECHT SECURITY GATE: PASSED")
		printContextBanner(stderr, payload)
		if resp.PreExistingCount > 0 {
			fmt.Fprintf(stderr, "ℹ️  PRE-EXISTING DEBT IN BASELINE: %d findings ignored\n", resp.PreExistingCount)
		}
		return 0
	}

	fmt.Fprintf(stderr, "report %s ingested, %d finding(s)\n", resp.ReportID, resp.TotalFindings)

	gate, err := cl.GetGateStatus(payload.Project, *severity)
	if err != nil {
		fmt.Fprintf(stderr, "error: gate check failed: %v\n", err)
		return 2
	}

	if gate.ThresholdBreached {
		fmt.Fprintf(stderr, "gate FAILED: %d blocking finding(s)\n", gate.BlockingCount)
		return 1
	}

	fmt.Fprintln(stderr, "gate PASSED: no blocking findings")
	return 0
}

func printContextBanner(w io.Writer, p client.IngestPayload) {
	fmt.Fprintf(w, "Project: %s | Scanner: %s", p.Project, p.Scanner)
	if p.Branch != "" || p.BaseRevision != "" {
		target := p.BaseRevision
		if target == "" {
			target = "baseline"
		}
		src := p.Branch
		if src == "" {
			src = "head"
		}
		fmt.Fprintf(w, " | Branch: %s -> %s", src, target)
	}
	fmt.Fprintln(w)
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

func getEnvAny(keys ...string) string {
	for _, k := range keys {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}

func printUsage(w io.Writer) {
	fmt.Fprintf(w, `Usage: specht-adapter [flags]

CI/CD gate-check adapter for Specht. Reads a scan result from stdin or a file,
ingests it, then evaluates gate status (change-scoped or project-wide) and
exits based on the policy result.

Flags:
  -project string        Project slug (overrides payload)
  -tool string           Scanner name (overrides payload)
  -exclude-tool string   Skip if scanner name matches this value
  -severity string       Severity threshold, comma-separated (default: high,critical)
  -status string         Finding status filter (default: open)
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
  API_URL                Specht API base URL (default "http://localhost:8080")
  API_KEY                API key for authentication (required)
  GITHUB_BASE_REF        Auto-detected PR target branch in GitHub Actions
  GITHUB_SHA             Auto-detected commit SHA in GitHub Actions
  GITHUB_REPOSITORY      Auto-detected GitHub repository (owner/repo)
  GITHUB_STEP_SUMMARY    Auto-detected path to Markdown job summary
  GITHUB_TOKEN           Auto-detected GitHub token
  CI_MERGE_REQUEST_TARGET_BRANCH_NAME Auto-detected MR target in GitLab CI

Exit codes:
  0  Pass - no blocking findings, or skipped by -exclude-tool
  1  Fail - blocking findings exist in change scope
  2  Error - API unreachable, invalid input, or configuration error

Examples:
  trivy image --format json myapp:latest | specht-adapter -project=my-app -introduced-only
  specht-adapter -file=scan.json -tool=trivy -project=my-app -base-ref=main
`)
}
