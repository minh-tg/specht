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
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/reqctx"
)

// Event names for the canonical security-relevant operations.
const (
	EventSSOExchange          = "auth.sso.exchange"
	EventLogin                = "auth.login"
	EventLogout               = "auth.logout"
	EventRegister             = "auth.register"
	EventCreateAPIKey         = "auth.apikey.create"
	EventListAPIKeys          = "auth.apikey.list"
	EventRevokeAPIKey         = "auth.apikey.revoke"
	EventIngestReport         = "scan.ingest"
	EventGetFinding           = "finding.view"
	EventListFindings         = "finding.list"
	EventTriageFinding        = "finding.triage"
	EventUndoTriage           = "finding.triage_undo"
	EventVerifyFix            = "finding.verify"
	EventCreateProject        = "project.create"
	EventUpdateProject        = "project.update"
	EventDeleteProject        = "project.delete"
	EventUpdateWaiver         = "waiver.update"
	EventDeleteWaiver         = "waiver.delete"
	EventToggleWaiver         = "waiver.toggle"
	EventRevokeWaiver         = "waiver.revoke"
	EventRestoreWaiver        = "waiver.restore"
	EventSetupComplete        = "setup.complete"
	EventChangeUserRole       = "user.role"
	EventChangePassword       = "user.password"
	EventResetLink            = "user.reset_link"
	EventResetPassword        = "user.reset_password"
	EventDeactivateUser       = "user.deactivate"
	EventReactivateUser       = "user.reactivate"
	EventRequestWaiver        = "waiver.request"
	EventApproveWaiver        = "waiver.approve"
	EventRejectWaiver         = "waiver.reject"
	EventWithdrawWaiver       = "waiver.withdraw"
	EventCreateInvite         = "invite.create"
	EventAcceptInvite         = "invite.accept"
	EventRevokeInvite         = "invite.revoke"
	EventDeleteReport         = "report.delete"
	EventUpdateWatcher        = "project.watcher.update"
	EventAddProjectMember     = "project.member.add"
	EventRemoveProjectMember  = "project.member.remove"
	EventAddTeamMember        = "team.member.add"
	EventRemoveTeamMember     = "team.member.remove"
	EventLinkProjectTeam      = "project.team.link"
	EventUnlinkProjectTeam    = "project.team.unlink"
	EventCreateTeam           = "team.create"
	EventDeleteTeam           = "team.delete"
	EventCreatePolicyTemplate = "policy.template.create"
	EventUpdatePolicyTemplate = "policy.template.update"
	EventDeletePolicyTemplate = "policy.template.delete"
	EventSetProjectPolicy     = "project.policy.set"
	EventUpdateEnvironment    = "project.environment.update"
	EventSetPolicyOverrides   = "project.policy.overrides"
	EventCreateWaiver         = "waiver.create"
	EventBulkTriage           = "finding.bulk_triage"
	EventCreateEvidence       = "evidence.create"
	EventDeleteEvidence       = "evidence.delete"
	EventAssessReachability   = "finding.reachability"
	EventSignoffFinding       = "finding.signoff"
	EventPurgeRetention       = "admin.retention.purge"
	EventUpdateProfile        = "user.profile"
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
		"project", clean(event.Project),
		"target", clean(event.Target),
		"request_id", clean(event.RequestID),
		"duration_ms", time.Since(event.StartedAt).Milliseconds(),
	}
	if event.Error != "" {
		fields = append(fields, "error", clean(event.Error))
	}
	a.logger.InfoContext(ctx, "audit", fields...)
}

// HTTP is a convenience wrapper: it extracts the identity from the request
// context, populates the principal, and logs.
func (a *Logger) HTTP(r *http.Request, name string, outcome Outcome, project, target string, err error) {
	ident := auth.ContextIdentity(r.Context())
	started := reqctx.Start(r.Context())
	if started.IsZero() {
		started = time.Now()
	}
	a.Log(r.Context(), Event{
		Name:      name,
		Outcome:   outcome,
		Principal: ident,
		Project:   project,
		Target:    target,
		RequestID: reqctx.ID(r.Context()),
		StartedAt: started,
		Error:     errMsg(err),
	})
}

// maxFieldBytes bounds one text field of an audit line. Longer values are cut,
// so a request cannot turn one event into a megabyte of log.
const maxFieldBytes = 512

// clean makes a value that came from a request safe to write on one log line.
// Control characters, DEL and the Unicode line and paragraph separators are
// replaced with visible escapes (\n, \x1b, \u2028), so a newline or an ANSI
// sequence in an email or a project name cannot forge a second event or
// repaint a terminal. Everything else is kept, and the result is cut to
// maxFieldBytes. The escaping does not depend on how the sink quotes values.
func clean(s string) string {
	if len(s) <= maxFieldBytes && !needsEscape(s) {
		return s
	}
	var b strings.Builder
	for i, r := range s {
		if b.Len() >= maxFieldBytes {
			b.WriteString("...")
			_ = i
			break
		}
		switch {
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r == utf8.RuneError || !isEscaped(r):
			b.WriteRune(r)
		case r < 0x100:
			fmt.Fprintf(&b, `\x%02x`, r)
		default:
			fmt.Fprintf(&b, `\u%04x`, r)
		}
	}
	return b.String()
}

func isEscaped(r rune) bool {
	return unicode.IsControl(r) || r == '\u2028' || r == '\u2029'
}

func needsEscape(s string) bool {
	for _, r := range s {
		if isEscaped(r) {
			return true
		}
	}
	return false
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
