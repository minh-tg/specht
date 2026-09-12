// Package audit provides structured audit logging for security-relevant
// operations. Each audit event is a slog entry with a stable "audit" field
// naming the action, plus principal, target, and outcome. Audit events are
// written via a dedicated *slog.Logger so they can be routed to a separate
// sink (file, SIEM, etc.) in production deployments.
//
// audit/observability.
package audit

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/xMinhx/specht/internal/auth"
)

// Event names for the canonical security-relevant operations.
const (
	EventLogin         = "auth.login"
	EventLogout        = "auth.logout"
	EventRegister      = "auth.register"
	EventCreateAPIKey  = "auth.apikey.create"
	EventListAPIKeys   = "auth.apikey.list"
	EventRevokeAPIKey  = "auth.apikey.revoke"
	EventIngestReport  = "scan.ingest"
	EventGetFinding    = "finding.view"
	EventListFindings  = "finding.list"
	EventTriageFinding = "finding.triage"
	EventVerifyFix     = "finding.verify"
	EventCreateProject = "project.create"
	EventUpdateProject = "project.update"
	EventDeleteProject = "project.delete"
	EventUpdateWaiver  = "waiver.update"
	EventToggleWaiver  = "waiver.toggle"
)

// Outcome describes the success or failure of an audited operation.
type Outcome int

const (
	OutcomeSuccess Outcome = iota
	OutcomeFailure
	OutcomeError
)

// Event is one structured audit log entry.
type Event struct {
	Name      string
	Outcome   Outcome
	Principal *auth.Identity
	Project   string
	Target    string
	RequestID string
	Error     string
	StartedAt time.Time
}

// Logger wraps a slog.Logger to emit structured audit entries.
type Logger struct {
	logger *slog.Logger
}

// NewLogger returns a Logger that writes audit entries to the given logger.
// A nil logger falls back to slog.Default().
func NewLogger(l *slog.Logger) *Logger {
	if l == nil {
		l = slog.Default()
	}
	return &Logger{logger: l}
}

// Log writes a structured audit event.
func (a *Logger) Log(ctx context.Context, event Event) {
	if a == nil {
		return
	}
	fields := []any{
		"audit", event.Name,
		"outcome", outcomeString(event.Outcome),
		"principal_id", principalID(event.Principal),
		"is_api_key", isAPIKey(event.Principal),
		"project", event.Project,
		"target", event.Target,
		"request_id", event.RequestID,
		"duration_ms", time.Since(event.StartedAt).Milliseconds(),
	}
	if event.Error != "" {
		fields = append(fields, "error", event.Error)
	}
	a.logger.InfoContext(ctx, "audit", fields...)
}

// HTTP is a convenience wrapper: it extracts the identity from the request
// context, populates the principal, and logs.
func (a *Logger) HTTP(r *http.Request, name string, outcome Outcome, project, target string, err error) {
	ident := auth.ContextIdentity(r.Context())
	a.Log(r.Context(), Event{
		Name:      name,
		Outcome:   outcome,
		Principal: ident,
		Project:   project,
		Target:    target,
		StartedAt: time.Now(),
		Error:     errMsg(err),
	})
}

func outcomeString(o Outcome) string {
	switch o {
	case OutcomeSuccess:
		return "success"
	case OutcomeFailure:
		return "failure"
	case OutcomeError:
		return "error"
	default:
		return "unknown"
	}
}

func principalID(ident *auth.Identity) string {
	if ident == nil {
		return ""
	}
	return ident.UserID
}

func isAPIKey(ident *auth.Identity) bool {
	return ident != nil && ident.IsAPIKey
}

func errMsg(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
