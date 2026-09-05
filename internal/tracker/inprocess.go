package tracker

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// InProcessTracker is a concrete Tracker that records issue operations in
// memory. It is useful for testing, and as a reference implementation of the
// Tracker contract. A real provider adapter (jira.go, linear.go) would follow
// the same interface with HTTP transport to the external service.
type InProcessTracker struct {
	mu     sync.Mutex
	issues map[string]IssueRecord
	logger func(string, ...any)
}

// IssueRecord is a single tracked issue.
type IssueRecord struct {
	ID          IssueID
	FindingID   string
	Project     string
	Severity    string
	Title       string
	State       string
	CreatedAt   time.Time
	UpdatedAt   time.Time
	Transitions []IssueTransition
}

// IssueTransition records one state transition applied to an issue.
type IssueTransition struct {
	From string
	To   string
	When time.Time
}

// NewInProcessTracker returns an InProcessTracker.
func NewInProcessTracker(logger func(string, ...any)) *InProcessTracker {
	return &InProcessTracker{
		issues: make(map[string]IssueRecord),
		logger: logger,
	}
}

func (t *InProcessTracker) CreateIssue(ctx context.Context, event Event) (IssueID, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if event.Type != EventCreated {
		return "", fmt.Errorf("inprocess: unexpected event type %s for CreateIssue", event.Type)
	}

	id := IssueID(fmt.Sprintf("ISSUE-%d", len(t.issues)+1))
	now := time.Now()
	record := IssueRecord{
		ID:        id,
		FindingID: event.FindingID,
		Project:   event.ProjectSlug,
		Severity:  event.Severity,
		Title:     event.Title,
		State:     "open",
		CreatedAt: now,
		UpdatedAt: now,
	}
	t.issues[string(id)] = record
	if t.logger != nil {
		t.logger("tracker create", "issue", string(id), "finding", event.FindingID, "severity", event.Severity)
	}
	return id, nil
}

func (t *InProcessTracker) UpdateIssue(ctx context.Context, issueID IssueID, event Event) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Resolve the issue: either by explicit IssueID or lookup by finding ID
	// when no external ID was recorded.
	var record IssueRecord
	var ok bool
	if issueID != "" {
		record, ok = t.issues[string(issueID)]
	} else {
		for _, r := range t.issues {
			if r.FindingID == event.FindingID {
				record, ok = r, true
				issueID = r.ID
				break
			}
		}
	}
	if !ok {
		return fmt.Errorf("inprocess: issue not found for finding %s", event.FindingID)
	}

	now := time.Now()
	var newState string
	switch event.Type {
	case EventVerifiedFixed:
		newState = "closed"
	case EventRegression, EventReopenedSeverity:
		newState = "reopened"
	default:
		return fmt.Errorf("inprocess: unsupported event type %s for UpdateIssue", event.Type)
	}

	oldState := record.State
	record.State = newState
	record.UpdatedAt = now
	record.Transitions = append(record.Transitions, IssueTransition{
		From: oldState,
		To:   newState,
		When: now,
	})
	t.issues[string(issueID)] = record
	if t.logger != nil {
		t.logger("tracker update", "issue", string(issueID), "finding", event.FindingID, "to", newState)
	}
	return nil
}

// Name returns the provider name.
func (t *InProcessTracker) Name() string { return "inprocess" }

// Issues returns a snapshot of all tracked issues.
func (t *InProcessTracker) Issues() []IssueRecord {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]IssueRecord, 0, len(t.issues))
	for _, r := range t.issues {
		out = append(out, r)
	}
	return out
}
