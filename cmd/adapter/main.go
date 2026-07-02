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
	Project string          `json:"project"`
	Scanner string          `json:"scanner"`
	RawData json.RawMessage `json:"raw_data"`
}

type apiError struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func main() {
	severity := flag.String("severity", "high,critical", "Severity threshold (comma-separated)")
	status := flag.String("status", "open", "Finding status filter")
	tool := flag.String("tool", "", "Scanner tool name filter (optional)")
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

	reportID, err := ingestReport(apiURL, apiKey, payload)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: ingest failed: %v\n", err)
		os.Exit(2)
	}

	fmt.Fprintf(os.Stderr, "report %s ingested, checking findings...\n", reportID)

	findings, err := checkFindings(apiURL, apiKey, payload.Project, *severity, *status, *tool)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: check failed: %v\n", err)
		os.Exit(2)
	}

	if len(findings) > 0 {
		fmt.Fprintf(os.Stderr, "gate FAILED: %d finding(s) at or above threshold (%s)\n", len(findings), *severity)
		for _, f := range findings {
			fmt.Fprintf(os.Stderr, "  - %s [%s] %s\n", f.Fingerprint, f.CurrentSeverity, f.CurrentTitle)
		}
		os.Exit(1)
	}

	fmt.Fprintln(os.Stderr, "gate PASSED: no findings at or above threshold")
	os.Exit(0)
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `Usage: specht-adapter [flags]

CI/CD gate-check adapter for Specht. Reads a scan result from stdin,
ingests it into Specht, and checks whether any findings meet or exceed
the severity threshold.

Flags:
  -project string    Project slug (overrides project in stdin payload)
  -severity string   Severity threshold, comma-separated (default "high,critical")
  -status string     Finding status filter (default "open")
  -tool string       Scanner tool name filter (optional, e.g. "trivy")
  -help              Show this usage message

Environment:
  API_URL    Specht API base URL (default "http://localhost:8080")
  API_KEY    API key for authentication (required)

Exit codes:
  0  Pass — no findings at or above threshold
  1  Fail — findings at or above threshold exist
  2  Error — API unreachable, invalid input, or configuration error

Examples:
  trivy image --format json myapp:latest | specht-adapter -project=my-app
  cat scan.json | specht-adapter -severity=critical
`)
}

func ingestReport(apiURL, apiKey string, payload ingestPayload) (string, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal payload: %w", err)
	}

	req, err := http.NewRequest("POST", apiURL+"/api/v1/reports", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("http post: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		var ae apiError
		if json.Unmarshal(respBody, &ae) == nil && ae.Error.Message != "" {
			return "", fmt.Errorf("%s: %s", resp.Status, ae.Error.Message)
		}
		return "", fmt.Errorf("%s: %s", resp.Status, string(respBody))
	}

	var result struct {
		ReportID string `json:"report_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}
	return result.ReportID, nil
}

type finding struct {
	Fingerprint     string `json:"fingerprint"`
	CurrentTitle    string `json:"current_title"`
	CurrentSeverity string `json:"current_severity"`
}

func checkFindings(apiURL, apiKey, project, severity, status, tool string) ([]finding, error) {
	path := fmt.Sprintf("/api/v1/projects/%s/findings?severity=%s&status=%s", project, severity, status)
	if tool != "" {
		path += "&tool=" + tool
	}

	req, err := http.NewRequest("GET", apiURL+path, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http get: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("project %q not found", project)
	}
	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("%s: %s", resp.Status, string(respBody))
	}

	var findings []finding
	if err := json.NewDecoder(resp.Body).Decode(&findings); err != nil {
		return nil, fmt.Errorf("decode findings: %w", err)
	}
	return findings, nil
}
