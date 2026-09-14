package notify

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// Channel names a notification channel family.
type Channel string

const (
	// ChannelIssue plans a linked work item (create/update/close).
	ChannelIssue Channel = "issue"
	// ChannelMessage plans a messaging notification with actionable links.
	ChannelMessage Channel = "message"
)

// Action names the sync operation a plan performs.
type Action string

const (
	// ActionCreate opens a new work item or sends a new message.
	ActionCreate Action = "create"
	// ActionUpdate refreshes the linked item to the finding's state.
	ActionUpdate Action = "update"
	// ActionClose resolves the linked item when the finding is fixed.
	ActionClose Action = "close"
)

// Input is the finding evidence one plan is built from.
type Input struct {
	FindingID     string
	Title         string
	Severity      string
	SeverityRank  int16
	FindingKind   string
	Fingerprint   string
	State         string
	ProjectSlug   string
	FindingURL    string
	Remediation   string
	Introduced    string
	Channel       Channel
	Target        string
	AlreadyLinked bool
}

// Plan is one reviewable notification action.
type Plan struct {
	ID        string  `json:"id"`
	Channel   Channel `json:"channel"`
	Target    string  `json:"target"`
	Action    Action  `json:"action"`
	Title     string  `json:"title"`
	Body      string  `json:"body"`
	Links     Links   `json:"links"`
	DedupeKey string  `json:"dedupe_key"`
	Reason    string  `json:"reason"`
}

// Links carries actionable references. All optional; empty stays empty.
type Links struct {
	Finding string `json:"finding,omitempty"`
	Project string `json:"project,omitempty"`
	Fix     string `json:"fix,omitempty"`
}

// Outcome is either a plan or an explicit refusal.
type Outcome struct {
	Supported bool   `json:"supported"`
	Plan      *Plan  `json:"plan,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

// Build plans the notification action for one finding's evidence. Channel
// must be issue or message with a non-empty target; anything else is an
// explicit refusal, never a partial plan.
func Build(in Input) Outcome {
	channel := Channel(strings.ToLower(strings.TrimSpace(string(in.Channel))))
	if channel != ChannelIssue && channel != ChannelMessage {
		return Outcome{Reason: fmt.Sprintf("unsupported channel %q: want %q or %q", in.Channel, ChannelIssue, ChannelMessage)}
	}
	if strings.TrimSpace(in.Target) == "" {
		return Outcome{Reason: "target is required (integration and scope)"}
	}
	if strings.TrimSpace(in.Fingerprint) == "" {
		return Outcome{Reason: "finding fingerprint is required for dedupe"}
	}
	action := actionFor(in)
	plan := &Plan{
		ID:        planID(channel, in.Target, in.Fingerprint),
		Channel:   channel,
		Target:    strings.TrimSpace(in.Target),
		Action:    action,
		Title:     planTitle(channel, in),
		Body:      planBody(in, action),
		DedupeKey: dedupeKey(channel, in.Target, in.Fingerprint),
		Reason:    planReason(channel, in, action),
		Links: Links{
			Finding: in.FindingURL,
			Fix:     in.Remediation,
		},
	}
	return Outcome{Supported: true, Plan: plan}
}

// actionFor derives the sync operation from lifecycle state: fixed closes,
// already-linked updates, otherwise creates. Unknown states create — a
// new state must never silently resolve a linked item.
func actionFor(in Input) Action {
	if strings.EqualFold(strings.TrimSpace(in.State), "fixed") {
		return ActionClose
	}
	if in.AlreadyLinked {
		return ActionUpdate
	}
	return ActionCreate
}

// dedupeKey scopes one finding to at most one work item per integration
// and scope: channel + target + fingerprint.
func dedupeKey(channel Channel, target, fingerprint string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{string(channel), target, fingerprint}, "\x00")))
	return "notify-" + hex.EncodeToString(sum[:])[:12]
}

// planID is deterministic like the dedupe key so identical evidence
// reproduces the identical plan.
func planID(channel Channel, target, fingerprint string) string {
	return dedupeKey(channel, target, fingerprint)
}

// planTitle renders the item/message subject with severity first.
func planTitle(channel Channel, in Input) string {
	severity := strings.ToUpper(strings.TrimSpace(in.Severity))
	if severity == "" {
		severity = "UNKNOWN"
	}
	if channel == ChannelMessage {
		return fmt.Sprintf("[%s] %s (%s)", severity, in.Title, actionVerb(actionFor(in)))
	}
	return fmt.Sprintf("[%s] %s", severity, in.Title)
}

// actionVerb humanizes the sync operation for message subjects.
func actionVerb(action Action) string {
	switch action {
	case ActionClose:
		return "resolved"
	case ActionUpdate:
		return "updated"
	default:
		return "new"
	}
}

// planBody renders the payload: what, where, fix, and introduced context.
// State transitions ride along so updates never lose current state.
func planBody(in Input, action Action) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s [%s/%s] state=%s action=%s", in.Title, in.FindingKind, in.Fingerprint, in.State, action)
	if in.Introduced != "" {
		fmt.Fprintf(&b, " introduced=%s", in.Introduced)
	}
	if in.Remediation != "" {
		fmt.Fprintf(&b, " fix=%s", in.Remediation)
	}
	if in.FindingURL != "" {
		fmt.Fprintf(&b, " finding=%s", in.FindingURL)
	}
	return b.String()
}

// planReason states why this action, for auditability.
func planReason(channel Channel, in Input, action Action) string {
	switch action {
	case ActionClose:
		return "finding is fixed: resolve the linked item"
	case ActionUpdate:
		return "finding changed: refresh the linked item to current state"
	default:
		return fmt.Sprintf("new %s for an unlinked finding", channel)
	}
}
