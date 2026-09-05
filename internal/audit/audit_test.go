package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"
)

func TestLoggerEmitsStructuredAuditEvent(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	auditLog := NewLogger(logger)

	ctx := context.Background()
	auditLog.Log(ctx, Event{
		Name:      EventIngestReport,
		Outcome:   OutcomeSuccess,
		Principal: nil,
		Project:   "my-project",
		Target:    "trivy",
	})

	line := buf.String()
	if line == "" {
		t.Fatal("expected audit log output")
	}

	var entry map[string]any
	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		t.Fatalf("unmarshal audit log: %v", err)
	}

	if entry["audit"] != "scan.ingest" {
		t.Errorf("audit event name = %v, want scan.ingest", entry["audit"])
	}
	if entry["outcome"] != "success" {
		t.Errorf("outcome = %v, want success", entry["outcome"])
	}
	if entry["project"] != "my-project" {
		t.Errorf("project = %v, want my-project", entry["project"])
	}
	if entry["target"] != "trivy" {
		t.Errorf("target = %v, want trivy", entry["target"])
	}
}

func TestLoggerErrorPropagated(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	auditLog := NewLogger(logger)

	ctx := context.Background()
	auditLog.Log(ctx, Event{
		Name:      EventLogin,
		Outcome:   OutcomeFailure,
		Principal: nil,
		Project:   "",
		Target:    "user@example.com",
		Error:     "invalid credentials",
	})

	var entry map[string]any
	if err := json.Unmarshal([]byte(buf.String()), &entry); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if entry["outcome"] != "failure" {
		t.Errorf("outcome = %v, want failure", entry["outcome"])
	}
	if entry["error"] != "invalid credentials" {
		t.Errorf("error = %v, want 'invalid credentials'", entry["error"])
	}
}

func TestOutcomeString(t *testing.T) {
	tests := []struct {
		outcome Outcome
		want    string
	}{
		{OutcomeSuccess, "success"},
		{OutcomeFailure, "failure"},
		{OutcomeError, "error"},
	}
	for _, tt := range tests {
		if got := outcomeString(tt.outcome); got != tt.want {
			t.Errorf("outcomeString(%d) = %q, want %q", tt.outcome, got, tt.want)
		}
	}
}
