package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/xMinhx/specht/internal/client"
)

func main() {
	severity := flag.String("severity", "", "Severity threshold (comma-separated, default: high,critical)")
	status := flag.String("status", "", "Finding status filter (default: open)")
	project := flag.String("project", "", "Project slug (overrides stdin)")
	tool := flag.String("tool", "", "Scanner name (overrides scanner detected in stdin payload)")
	excludeTool := flag.String("exclude-tool", "", "Skip if scanner matches this name")
	file := flag.String("file", "", "Path to scan result file (default: read from stdin)")
	introducedOnly := flag.Bool("introduced-only", false, "Gate strictly on introduced vulnerabilities")
	baseRef := flag.String("base-ref", "", "Baseline git ref/branch/commit (e.g. main)")
	commit := flag.String("commit", "", "Current commit SHA")
	branch := flag.String("branch", "", "Current branch name")
	scanMode := flag.String("scan-mode", "", "Scan mode: full or incremental")
	baselinePolicy := flag.String("baseline-policy", "warn", "Missing baseline action: warn or fail (default: warn)")
	help := flag.Bool("help", false, "Show usage")
	flag.Parse()

	if *help {
		printUsage()
		os.Exit(0)
	}

	detectCIEnvironment(baseRef, commit, branch)

	apiURL := os.Getenv("API_URL")
	if apiURL == "" {
		apiURL = "http://localhost:8080"
	}
	apiURL = strings.TrimRight(apiURL, "/")

	apiKey := os.Getenv("API_KEY")
	if apiKey == "" {
		fmt.Fprintln(os.Stderr, "error: API_KEY environment variable is required")
		os.Exit(2)
	}

	var rawInput []byte
	var err error
	if *file != "" {
		rawInput, err = os.ReadFile(*file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: reading file %q: %v\n", *file, err)
			os.Exit(2)
		}
	} else {
		rawInput, err = io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: reading stdin: %v\n", err)
			os.Exit(2)
		}
	}

	if len(bytes.TrimSpace(rawInput)) == 0 {
		fmt.Fprintln(os.Stderr, "error: input is empty, provide a scan result file or pipe to stdin")
		os.Exit(2)
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
		fmt.Fprintln(os.Stderr, "error: scanner is required (use -tool flag or specify in payload)")
		os.Exit(2)
	}

	if *excludeTool != "" && strings.EqualFold(payload.Scanner, *excludeTool) {
		fmt.Fprintf(os.Stderr, "skipped: scanner %q excluded by -exclude-tool flag\n", payload.Scanner)
		os.Exit(0)
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

	cl := client.New(apiURL, client.WithToken(apiKey))

	resp, err := cl.IngestReport(&payload)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: ingest failed: %v\n", err)
		os.Exit(2)
	}

	if resp.FallbackReason != "" {
		fmt.Fprintf(os.Stderr, "⚠️  BASELINE WARNING: %s\n", resp.FallbackReason)
		if strings.EqualFold(*baselinePolicy, "fail") {
			fmt.Fprintln(os.Stderr, "gate FAILED: missing baseline under baseline-policy=fail")
			os.Exit(1)
		}
	}

	if isIntroducedOnly {
		if resp.ThresholdBreached {
			fmt.Fprintln(os.Stderr, "❌ SPECHT SECURITY GATE: FAILED")
			printContextBanner(payload)
			fmt.Fprintf(os.Stderr, "\n🚨 NEW BLOCKING FINDINGS INTRODUCED IN THIS CHANGE: %d\n", resp.IntroducedCount)
			if resp.PreExistingCount > 0 {
				fmt.Fprintf(os.Stderr, "ℹ️  PRE-EXISTING DEBT IN BASELINE: %d findings ignored for this gate\n", resp.PreExistingCount)
			}
			os.Exit(1)
		}

		fmt.Fprintln(os.Stderr, "✅ SPECHT SECURITY GATE: PASSED")
		printContextBanner(payload)
		if resp.PreExistingCount > 0 {
			fmt.Fprintf(os.Stderr, "ℹ️  PRE-EXISTING DEBT IN BASELINE: %d findings ignored\n", resp.PreExistingCount)
		}
		os.Exit(0)
	}

	fmt.Fprintf(os.Stderr, "report %s ingested, %d finding(s)\n", resp.ReportID, resp.TotalFindings)

	gate, err := cl.GetGateStatus(payload.Project, *severity)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: gate check failed: %v\n", err)
		os.Exit(2)
	}

	if gate.ThresholdBreached {
		fmt.Fprintf(os.Stderr, "gate FAILED: %d blocking finding(s)\n", gate.BlockingCount)
		os.Exit(1)
	}

	fmt.Fprintln(os.Stderr, "gate PASSED: no blocking findings")
	os.Exit(0)
}

func printContextBanner(p client.IngestPayload) {
	fmt.Fprintf(os.Stderr, "Project: %s | Scanner: %s", p.Project, p.Scanner)
	if p.Branch != "" || p.BaseRevision != "" {
		target := p.BaseRevision
		if target == "" {
			target = "baseline"
		}
		src := p.Branch
		if src == "" {
			src = "head"
		}
		fmt.Fprintf(os.Stderr, " | Branch: %s -> %s", src, target)
	}
	fmt.Fprintln(os.Stderr)
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

func printUsage() {
	fmt.Fprintf(os.Stderr, `Usage: specht-adapter [flags]

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
  -help                  Show this usage message

Environment:
  API_URL                Specht API base URL (default "http://localhost:8080")
  API_KEY                API key for authentication (required)
  GITHUB_BASE_REF        Auto-detected PR target branch in GitHub Actions
  GITHUB_SHA             Auto-detected commit SHA in GitHub Actions
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
