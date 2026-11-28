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
	// needsYouLimit bounds the items listed of each kind. NeedsYouTotals counts beyond it.
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
// every request to decide, waiver ending and assigned finding, listed or not, and the answers
// from the last three days. Older answers stay listed for 14 days without counting.
type NeedsYouResponse struct {
	Count int            `json:"count"`
	Items []NeedsYouItem `json:"items"`
	// Totals is how many items of each kind exist. Items lists at most needsYouLimit of a kind.
	Totals NeedsYouTotals `json:"totals"`
}

// NeedsYouTotals counts the items of each kind, including those beyond the listed ones.
type NeedsYouTotals struct {
	WaiverToDecide  int `json:"waiver_to_decide"`
	WaiverEnding    int `json:"waiver_ending"`
	FindingAssigned int `json:"finding_assigned"`
	RequestDecided  int `json:"request_decided"`
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
	for _, w := range toDecide.Items {
		item := waiverItem(NeedsYouWaiverToDecide, w)
		item.Detail = w.Reason
		out.Items = append(out.Items, item)
	}
	out.Totals.WaiverToDecide = toDecide.Total

	if len(managed) > 0 {
		ending, err := store.ListWaiversEnding(ctx, managed, now, now.Add(WaiverExpiryWarning), needsYouLimit)
		if err != nil {
			return nil, fmt.Errorf("list waivers ending: %w", err)
		}
		for _, w := range ending.Items {
			item := waiverItem(NeedsYouWaiverEnding, w)
			item.Link = waiversTab(w.ProjectSlug, waiversInForce)
			out.Items = append(out.Items, item)
		}
		out.Totals.WaiverEnding = ending.Total
	}

	assigned, err := store.ListOpenFindingsAssignedTo(ctx, ident.UserID, reach, needsYouLimit)
	if err != nil {
		return nil, fmt.Errorf("list assigned findings: %w", err)
	}
	for _, f := range assigned.Items {
		out.Items = append(out.Items, NeedsYouItem{
			Kind: NeedsYouFindingAssigned, ProjectSlug: f.ProjectSlug, ProjectName: f.ProjectName,
			Title: f.Title, Severity: f.Severity, At: f.LastSeenAt,
			Link: "/" + f.ProjectSlug + "/findings/" + f.ID,
		})
	}
	out.Totals.FindingAssigned = assigned.Total

	answers, err := store.ListDecidedWaiverRequests(ctx, ident.UserID, reach,
		now.Add(-needsYouDecidedWindow), now.Add(-needsYouFreshAnswer), needsYouLimit)
	if err != nil {
		return nil, fmt.Errorf("list decided requests: %w", err)
	}
	for _, w := range answers.Items {
		item := waiverItem(NeedsYouRequestDecided, w)
		item.Status = answerStatus(w)
		item.Detail = w.DecisionNote
		if inForce(w, now) {
			item.Link = waiversTab(w.ProjectSlug, waiversInForce)
		} else {
			item.Link = waiversTab(w.ProjectSlug, waiversClosed)
		}
		out.Items = append(out.Items, item)
	}
	out.Totals.RequestDecided = answers.Total

	out.Count = out.Totals.WaiverToDecide + out.Totals.WaiverEnding + out.Totals.FindingAssigned + answers.Fresh
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

// requestsToDecide lists the pending requests the caller may decide, by the rule checkSelfApproval
// applies: a global admin decides their own request too, and anyone else's own request waits on
// someone else unless nobody else can decide it. The store leaves out the hidden ones, so the
// total counts only what the caller may decide.
func (u *Usecases) requestsToDecide(ctx context.Context, ident *auth.Identity, managed []string) (port.NeedsYouWaivers, error) {
	if len(managed) == 0 {
		return port.NeedsYouWaivers{}, nil
	}
	store := u.deps.Stores.NeedsYou
	hideOwnIn := []string{}
	if ident.Role != auth.RoleAdmin {
		own, err := store.ListProjectsWithOwnPendingRequests(ctx, ident.UserID, managed)
		if err != nil {
			return port.NeedsYouWaivers{}, fmt.Errorf("list projects with own requests: %w", err)
		}
		for _, projectID := range own {
			sole, err := u.soleWaiverDecider(ctx, projectID, ident.UserID)
			if err != nil {
				return port.NeedsYouWaivers{}, err
			}
			if !sole {
				hideOwnIn = append(hideOwnIn, projectID)
			}
		}
	}
	pending, err := store.ListPendingWaiverRequests(ctx, ident.UserID, managed, hideOwnIn, needsYouLimit)
	if err != nil {
		return port.NeedsYouWaivers{}, fmt.Errorf("list pending waiver requests: %w", err)
	}
	return pending, nil
}

// The tabs of the Waivers page, by the value of its state query parameter. Waiting, for pending
// requests, is the page's default and needs no parameter.
const (
	waiversInForce = "in_force"
	waiversClosed  = "closed"
)

// waiverItem links to the Waiting tab, where a pending request is; the caller relinks other kinds.
func waiverItem(kind string, w port.NeedsYouWaiver) NeedsYouItem {
	return NeedsYouItem{
		Kind: kind, ProjectSlug: w.ProjectSlug, ProjectName: w.ProjectName, Title: w.Name,
		At: w.At, Link: "/" + w.ProjectSlug + "/waivers",
	}
}

func waiversTab(slug, tab string) string {
	return "/" + slug + "/waivers?state=" + tab
}

// inForce reports whether an answered request is a waiver that lets findings through now, the
// rule the Waivers page sorts its In force tab by: approved, switched on and not past its end.
// A revoked or lapsed approval sits on the Closed tab with the rejections.
func inForce(w port.NeedsYouWaiver, now time.Time) bool {
	return w.Status == WaiverStatusApproved && w.Enabled && (w.ExpiresAt == nil || w.ExpiresAt.After(now))
}

// answerStatus names how a request ended: a lapse with no reviewer is "expired", not "rejected".
func answerStatus(w port.NeedsYouWaiver) string {
	if w.DecisionReason == "expired" {
		return "expired"
	}
	return w.Status
}
