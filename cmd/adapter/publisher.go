package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/minh-tg/specht/internal/client"
)

// escapeCommandProperty escapes special characters for GitHub Actions workflow command properties.
func escapeCommandProperty(s string) string {
	s = strings.ReplaceAll(s, "%", "%25")
	s = strings.ReplaceAll(s, "\r", "%0D")
	s = strings.ReplaceAll(s, "\n", "%0A")
	s = strings.ReplaceAll(s, ":", "%3A")
	s = strings.ReplaceAll(s, ",", "%2C")
	return s
}

// escapeCommandData escapes special characters for GitHub Actions workflow command messages.
func escapeCommandData(s string) string {
	s = strings.ReplaceAll(s, "%", "%25")
	s = strings.ReplaceAll(s, "\r", "%0D")
	s = strings.ReplaceAll(s, "\n", "%0A")
	return s
}

// emitGitHubWorkflowAnnotations formats annotations as GitHub Actions workflow commands.
// Reference: https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions
func emitGitHubWorkflowAnnotations(w io.Writer, annotations []client.PRCheckAnnotation) {
	for _, a := range annotations {
		cmd := "error"
		switch strings.ToLower(a.Level) {
		case "warning":
			cmd = "warning"
		case "info", "notice":
			cmd = "notice"
		}

		var props []string
		if a.File != "" {
			props = append(props, fmt.Sprintf("file=%s", escapeCommandProperty(a.File)))
		}
		if a.StartLine > 0 {
			props = append(props, fmt.Sprintf("line=%d", a.StartLine))
		}
		if a.EndLine > 0 && a.EndLine >= a.StartLine {
			props = append(props, fmt.Sprintf("endLine=%d", a.EndLine))
		}
		if a.Title != "" {
			props = append(props, fmt.Sprintf("title=%s", escapeCommandProperty(a.Title)))
		}

		propStr := ""
		if len(props) > 0 {
			propStr = " " + strings.Join(props, ",")
		}

		msg := escapeCommandData(a.Message)
		fmt.Fprintf(w, "::%s%s::%s\n", cmd, propStr, msg)
	}
}

// writeStepSummary writes or appends the check markdown summary to the specified file (typically GITHUB_STEP_SUMMARY).
func writeStepSummary(filePath string, summary string) error {
	if filePath == "" || summary == "" {
		return nil
	}
	f, err := os.OpenFile(filePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open summary file: %w", err)
	}
	defer f.Close()

	if _, err := fmt.Fprintf(f, "%s\n\n", strings.TrimSpace(summary)); err != nil {
		return fmt.Errorf("write summary: %w", err)
	}
	return nil
}

type gitHubCheckRunRequest struct {
	Name       string               `json:"name"`
	HeadSHA    string               `json:"head_sha"`
	Status     string               `json:"status"`
	Conclusion string               `json:"conclusion"`
	Output     gitHubCheckRunOutput `json:"output"`
}

type gitHubCheckRunOutput struct {
	Title       string                     `json:"title"`
	Summary     string                     `json:"summary"`
	Annotations []gitHubCheckRunAnnotation `json:"annotations,omitempty"`
}

type gitHubCheckRunAnnotation struct {
	Path            string `json:"path"`
	StartLine       int    `json:"start_line"`
	EndLine         int    `json:"end_line"`
	AnnotationLevel string `json:"annotation_level"`
	Message         string `json:"message"`
	Title           string `json:"title,omitempty"`
}

// checkRunAnnotationLevel maps a preview annotation level to the Checks API
// annotation level.
func checkRunAnnotationLevel(level string) string {
	switch strings.ToLower(level) {
	case "warning":
		return "warning"
	case "info", "notice":
		return "notice"
	default:
		return "failure"
	}
}

// toCheckRunAnnotation converts one preview annotation, skipping entries
// without a file path.
func toCheckRunAnnotation(a client.PRCheckAnnotation) (gitHubCheckRunAnnotation, bool) {
	if a.File == "" {
		return gitHubCheckRunAnnotation{}, false
	}
	startLine := a.StartLine
	if startLine <= 0 {
		startLine = 1
	}
	endLine := a.EndLine
	if endLine < startLine {
		endLine = startLine
	}
	return gitHubCheckRunAnnotation{
		Path:            a.File,
		StartLine:       startLine,
		EndLine:         endLine,
		AnnotationLevel: checkRunAnnotationLevel(a.Level),
		Message:         a.Message,
		Title:           a.Title,
	}, true
}

// publishGitHubCheckRun posts a check run to the GitHub Checks API.
func publishGitHubCheckRun(ctx context.Context, hc *http.Client, token, repo, commit string, preview *client.PRCheckPreview) error {
	if token == "" || repo == "" || commit == "" || preview == nil {
		return nil
	}
	if hc == nil {
		hc = http.DefaultClient
	}

	conclusion := preview.Conclusion
	if conclusion == "" {
		conclusion = "neutral"
	}

	var ghAnnotations []gitHubCheckRunAnnotation
	for _, a := range preview.Annotations {
		if ann, ok := toCheckRunAnnotation(a); ok {
			ghAnnotations = append(ghAnnotations, ann)
		}
	}

	payload := gitHubCheckRunRequest{
		Name:       "Specht Security Gate",
		HeadSHA:    commit,
		Status:     "completed",
		Conclusion: conclusion,
		Output: gitHubCheckRunOutput{
			Title:       preview.Title,
			Summary:     preview.Summary,
			Annotations: ghAnnotations,
		},
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal check run payload: %w", err)
	}

	reqURL := fmt.Sprintf("https://api.github.com/repos/%s/check-runs", repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("create check run request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Content-Type", "application/json")

	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("post check run: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("github api returned status %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}
