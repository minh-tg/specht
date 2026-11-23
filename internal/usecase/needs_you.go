package usecase

import (
	"context"
	"fmt"
	"time"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
)

// The kinds of thing that wait on a person.
const (
	// NeedsYouWaiverToDecide is a pending waiver request the caller may approve or reject.
	NeedsYouWaiverToDecide = "waiver_to_decide"
	// NeedsYouRequestDecided is the answer to a request the caller made.
	NeedsYouRequestDecided = "request_decided"
	// NeedsYouWaiverEnding is an approved waiver on a project the caller manages that ends soon,
	// after which its findings block again.
	NeedsYouWaiverEnding = "waiver_ending"
	// NeedsYouFindingAssigned is an open finding assigned to the caller.
	NeedsYouFindingAssigned = "finding_assigned"
)

const (
	// needsYouDecidedWindow is how long an answer to the caller's own request stays listed.
	needsYouDecidedWindow = 14 * 24 * time.Hour
	// needsYouFreshAnswer is how long an answer counts toward the badge. The list keeps no
	// read marks, so an older answer is shown but no longer asks for attention.
	needsYouFreshAnswer = 3 * 24 * time.Hour
	// needsYouLimit bounds each kind. The count of assigned findings is exact beyond it.
	needsYouLimit = 50
)

// NeedsYouItem is one thing waiting on the caller.
type NeedsYouItem struct {
	Kind        string `json:"kind"`
	ProjectSlug string `json:"project_slug"`
	ProjectName string `json:"project_name"`
	// Title is the waiver's name or the finding's title.
	Title string `json:"title"`
	// Status is "approved", "rejected" or "expired" for an answered request.
	Status string `json:"status,omitempty"`
	// Detail is the request's reason, or the reviewer's note on an answer.
	Detail   string    `json:"detail,omitempty"`
	Severity string    `json:"severity,omitempty"`
	At       time.Time `json:"at"`
	// Link is the app path that opens the thing.
	Link string `json:"link"`
}

// NeedsYouResponse is everything waiting on the caller. Count is what the navigation badge shows:
// the items that ask for action, and answers newer than three days.
type NeedsYouResponse struct {
	Count int            `json:"count"`
	Items []NeedsYouItem `json:"items"`
	// AssignedFindings is the exact number of open findings assigned to the caller, which can
	// exceed the findings listed.
	AssignedFindings int `json:"assigned_findings"`
}

// GetNeedsYou lists what waits on the signed-in person across the projects they can reach:
// waiver requests they may decide, answers to their own requests, approved waivers on projects
// they manage that end within WaiverExpiryWarning, and open findings assigned to them. It keeps
// no read marks, so an item stays until its cause is gone or its time window passes.
func (u *Usecases) GetNeedsYou(ctx context.Context) (*NeedsYouResponse, error) {
	ident := auth.ContextIdentity(ctx)
	if ident == nil || ident.IsAPIKey {
		return nil, ErrProjectAccessDenied
	}
	out := &NeedsYouResponse{Items: []NeedsYouItem{}}
	projects, err := u.visibleProjects(ctx)
	if err != nil {
		return nil, err
	}
	if len(projects) == 0 || u.deps.Stores.NeedsYou == nil {
		return out, nil
	}
	reach := make([]string, len(projects))
	for i, p := range projects {
		reach[i] = p.ID
	}
	store := u.deps.Stores.NeedsYou
	now := u.clock()

	managed := reach
	if ident.Role != auth.RoleAdmin {
		managed, err = u.managedAmong(ctx, ident.UserID, reach)
		if err != nil {
			return nil, err
		}
	}

	toDecide, err := u.requestsToDecide(ctx, ident, managed)
	if err != nil {
		return nil, err
	}
	out.Items = append(out.Items, toDecide...)

	if len(managed) > 0 {
		ending, err := store.ListWaiversEnding(ctx, managed, now, now.Add(WaiverExpiryWarning), needsYouLimit)
		if err != nil {
			return nil, fmt.Errorf("list waivers ending: %w", err)
		}
		for _, w := range ending {
			out.Items = append(out.Items, waiverItem(NeedsYouWaiverEnding, w))
		}
	}

	assigned, err := store.ListOpenFindingsAssignedTo(ctx, ident.UserID, reach, needsYouLimit)
	if err != nil {
		return nil, fmt.Errorf("list assigned findings: %w", err)
	}
	for _, f := range assigned {
		out.Items = append(out.Items, NeedsYouItem{
			Kind: NeedsYouFindingAssigned, ProjectSlug: f.ProjectSlug, ProjectName: f.ProjectName,
			Title: f.Title, Severity: f.Severity, At: f.LastSeenAt,
			Link: "/" + f.ProjectSlug + "/findings/" + f.ID,
		})
	}
	total, err := store.CountOpenFindingsAssignedTo(ctx, ident.UserID, reach)
	if err != nil {
		return nil, fmt.Errorf("count assigned findings: %w", err)
	}
	out.AssignedFindings = int(total)

	answers, err := store.ListDecidedWaiverRequests(ctx, ident.UserID, reach, now.Add(-needsYouDecidedWindow), needsYouLimit)
	if err != nil {
		return nil, fmt.Errorf("list decided requests: %w", err)
	}
	fresh := 0
	for _, w := range answers {
		item := waiverItem(NeedsYouRequestDecided, w)
		item.Status = answerStatus(w)
		item.Detail = w.DecisionNote
		out.Items = append(out.Items, item)
		if now.Sub(w.At) <= needsYouFreshAnswer {
			fresh++
		}
	}

	out.Count = len(toDecide) + int(total) + fresh
	for _, item := range out.Items {
		if item.Kind == NeedsYouWaiverEnding {
			out.Count++
		}
	}
	return out, nil
}

// managedAmong narrows the reachable projects to those where the caller may decide waiver requests.
func (u *Usecases) managedAmong(ctx context.Context, userID string, reach []string) ([]string, error) {
	managed, err := u.deps.Stores.NeedsYou.ListManagedProjectIDs(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("list managed projects: %w", err)
	}
	reachable := make(map[string]bool, len(reach))
	for _, id := range reach {
		reachable[id] = true
	}
	out := make([]string, 0, len(managed))
	for _, id := range managed {
		if reachable[id] {
			out = append(out, id)
		}
	}
	return out, nil
}

// requestsToDecide lists the pending requests the caller may decide, by the rule ApproveWaiver
// applies: a person's own request waits on someone else, unless nobody else can decide it.
func (u *Usecases) requestsToDecide(ctx context.Context, ident *auth.Identity, managed []string) ([]NeedsYouItem, error) {
	if len(managed) == 0 {
		return nil, nil
	}
	pending, err := u.deps.Stores.NeedsYou.ListPendingWaiverRequests(ctx, managed, 2*needsYouLimit)
	if err != nil {
		return nil, fmt.Errorf("list pending waiver requests: %w", err)
	}
	alone := map[string]bool{}
	var items []NeedsYouItem
	for _, w := range pending {
		if w.RequestedBy == ident.UserID {
			sole, known := alone[w.ProjectID]
			if !known {
				sole, err = u.soleWaiverDecider(ctx, w.ProjectID, ident.UserID)
				if err != nil {
					return nil, err
				}
				alone[w.ProjectID] = sole
			}
			if !sole {
				continue
			}
		}
		item := waiverItem(NeedsYouWaiverToDecide, w)
		item.Detail = w.Reason
		items = append(items, item)
	}
	return items, nil
}

func waiverItem(kind string, w port.NeedsYouWaiver) NeedsYouItem {
	return NeedsYouItem{
		Kind: kind, ProjectSlug: w.ProjectSlug, ProjectName: w.ProjectName, Title: w.Name,
		At: w.At, Link: "/" + w.ProjectSlug + "/waivers",
	}
}

// answerStatus names how a request ended: a lapse with no reviewer is "expired", not "rejected".
func answerStatus(w port.NeedsYouWaiver) string {
	if w.DecisionReason == "expired" {
		return "expired"
	}
	return w.Status
}
