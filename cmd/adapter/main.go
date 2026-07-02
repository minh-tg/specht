package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

type ingestPayload struct {
	Project      string          `json:"project"`
	Scanner      string          `json:"scanner"`
	RawData      json.RawMessage `json:"raw_data"`
	GateSeverity string          `json:"gate_severity,omitempty"`
	GateStatus   string          `json:"gate_status,omitempty"`
}

type ingestResponse struct {
	ReportID          string `json:"report_id"`
	TotalFindings     int    `json:"total_findings"`
	ThresholdBreached bool   `json:"threshold_breached"`
}

type apiError struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func main() {
	severity := flag.String("severity", "", "Severity threshold (comma-separated, default: high,critical)")
	status := flag.String("status", "", "Finding status filter (default: open)")
	project := flag.String("project", "", "Project slug (overrides stdin)")
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

	var payload ingestPayload
	if err := json.Unmarshal(stdin, &payload); err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid JSON on stdin: %v\n", err)
		os.Exit(2)
	}

	if *project != "" {
		payload.Project = *project
	}

	if payload.Scanner == "" {
		fmt.Fprintln(os.Stderr, "error: scanner is required in stdin payload")
		os.Exit(2)
	}

	if *severity != "" {
		payload.GateSeverity = *severity
	}
	if *status != "" {
		payload.GateStatus = *status
	}

	resp, err := ingestReport(apiURL, apiKey, payload)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: ingest failed: %v\n", err)
		os.Exit(2)
	}

	fmt.Fprintf(os.Stderr, "report %s ingested, %d finding(s)\n", resp.ReportID, resp.TotalFindings)

	if resp.ThresholdBreached {
		fmt.Fprintln(os.Stderr, "gate FAILED: findings at or above threshold")
		os.Exit(1)
	}

	fmt.Fprintln(os.Stderr, "gate PASSED: no findings at or above threshold")
	os.Exit(0)
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `Usage: specht-adapter [flags]

CI/CD gate-check adapter for Specht. Reads a scan result from stdin,
ingests it, and exits based on server-side gating evaluation.

Flags:
  -project string   Project slug (overrides project in stdin payload)
  -severity string  Severity threshold, comma-separated (default: high,critical)
  -status string    Finding status filter (default: open)
  -help             Show this usage message

Environment:
  API_URL   Specht API base URL (default "http://localhost:8080")
  API_KEY   API key for authentication (required)

Exit codes:
  0  Pass - no findings at or above threshold
  1  Fail - findings at or above threshold exist
  2  Error - API unreachable, invalid input, or configuration error

Examples:
  trivy image --format json myapp:latest | specht-adapter -project=my-app
  cat scan.json | specht-adapter -severity=critical
`)
}

func ingestReport(apiURL, apiKey string, payload ingestPayload) (*ingestResponse, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}

	req, err := http.NewRequest("POST", apiURL+"/api/v1/reports", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http post: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		var ae apiError
		if json.Unmarshal(respBody, &ae) == nil && ae.Error.Message != "" {
			return nil, fmt.Errorf("%s: %s", resp.Status, ae.Error.Message)
		}
		return nil, fmt.Errorf("%s: %s", resp.Status, string(respBody))
	}

	var result ingestResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &result, nil
}
