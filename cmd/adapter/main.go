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
	help := flag.Bool("help", false, "Show usage")
	flag.Parse()

	if *help {
		printUsage()
		os.Exit(0)
	}

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

	stdin, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: reading stdin: %v\n", err)
		os.Exit(2)
	}
	if len(bytes.TrimSpace(stdin)) == 0 {
		fmt.Fprintln(os.Stderr, "error: stdin is empty, pipe a scan result")
		os.Exit(2)
	}

	var payload client.IngestPayload
	if err := json.Unmarshal(stdin, &payload); err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid JSON on stdin: %v\n", err)
		os.Exit(2)
	}

	if *project != "" {
		payload.Project = *project
	}

	if *tool != "" {
		payload.Scanner = *tool
	}

	if payload.Scanner == "" {
		fmt.Fprintln(os.Stderr, "error: scanner is required in stdin payload")
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

	cl := client.New(apiURL, client.WithToken(apiKey))

	resp, err := cl.IngestReport(&payload)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: ingest failed: %v\n", err)
		os.Exit(2)
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

func printUsage() {
	fmt.Fprintf(os.Stderr, `Usage: specht-adapter [flags]

CI/CD gate-check adapter for Specht. Reads a scan result from stdin,
ingests it, then checks project gate status and exits based on result.

Flags:
  -project string     Project slug (overrides project in stdin payload)
  -tool string        Scanner name (overrides scanner detected in stdin payload)
  -exclude-tool string Skip if scanner name matches this value
  -severity string    Severity threshold, comma-separated (default: high,critical)
  -status string      Finding status filter (default: open)
  -help               Show this usage message

Environment:
  API_URL   Specht API base URL (default "http://localhost:8080")
  API_KEY   API key for authentication (required)

Exit codes:
  0  Pass - no blocking findings, or skipped by -exclude-tool
  1  Fail - blocking findings exist (review required, expired waiver, etc.)
  2  Error - API unreachable, invalid input, or configuration error

Examples:
  trivy image --format json myapp:latest | specht-adapter -project=my-app
  cat scan.json | specht-adapter -severity=critical -tool=trivy
  find . -name 'results.json' -exec specht-adapter -tool=semgrep {} +
`)
}
