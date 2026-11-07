package usecase

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
)

// ErrAssigneeNotMember is returned when the person is not in the finding's project.
var ErrAssigneeNotMember = errors.New("that person is not a member of this project")

// AssignFinding sets who owns a finding, or nobody with an empty id. A manager can
// assign anyone in the project. A member can take a finding nobody owns or let go of
// their own, which is the common case on a small team and changes no verdict.
func (u *Usecases) AssignFinding(ctx context.Context, findingID, assigneeID string) (*AssigneeResponse, error) {
	fid, err := uuid.Parse(findingID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidFindingID, err)
	}
	finding, err := u.deps.Stores.Findings.GetByID(ctx, fid.String())
	if err != nil {
		if errors.Is(err, port.ErrNotFound) {
			return nil, ErrFindingNotFound
		}
		return nil, fmt.Errorf("get finding: %w", err)
	}
	if err := u.checkFindingVisibility(ctx, finding.ProjectID); err != nil {
		return nil, err
	}
	role, err := u.callerProjectRole(ctx, finding.ProjectID)
	if err != nil {
		return nil, err
	}
	ident := auth.ContextIdentity(ctx)
	if !isManagerRole(role) && assigneeID != "" && assigneeID != ident.UserID {
		return nil, ErrProjectAccessDenied
	}

	var assignee *AssigneeResponse
	if assigneeID != "" {
		if _, err := uuid.Parse(assigneeID); err != nil {
			return nil, ErrAssigneeNotMember
		}
		if err := u.requirePersonInProject(ctx, finding.ProjectID, assigneeID); err != nil {
			return nil, err
		}
		assignee = &AssigneeResponse{UserID: assigneeID}
	}

	existing, err := u.deps.Stores.Findings.ListAssignees(ctx, []string{fid.String()})
	if err != nil {
		return nil, fmt.Errorf("read the assignee: %w", err)
	}
	current, assigned := existing[fid.String()]
	// A member can take what nobody owns and let go of their own. Someone else's
	// finding stays theirs until a manager or they change it.
	if assigned && current.UserID != ident.UserID && !isManagerRole(role) {
		return nil, ErrProjectAccessDenied
	}

	if err := u.deps.Stores.Findings.SetAssignee(ctx, fid.String(), assigneeID); err != nil {
		return nil, fmt.Errorf("set assignee: %w", err)
	}
	if _, err := u.deps.Stores.Findings.CreateEvent(ctx, port.FindingEventInput{
		FindingID: fid.String(),
		EventType: "assigned",
		UserID:    &ident.UserID,
		Changes:   mustMarshal(map[string]any{"assignee_id": assigneeID, "previous_assignee_id": current.UserID}),
	}); err != nil {
		return nil, fmt.Errorf("log assignment: %w", err)
	}
	if assignee != nil {
		named, err := u.deps.Stores.Findings.ListAssignees(ctx, []string{fid.String()})
		if err != nil {
			return nil, fmt.Errorf("read the assignee: %w", err)
		}
		assignee.Name = named[fid.String()].Name
	}
	return assignee, nil
}

// requirePersonInProject accepts a direct or team member and a global admin, who
// can open every project.
func (u *Usecases) requirePersonInProject(ctx context.Context, projectID, userID string) error {
	_, err := u.deps.Stores.Projects.EffectiveRole(ctx, projectID, userID)
	if err == nil {
		return nil
	}
	if !errors.Is(err, port.ErrNotFound) {
		return fmt.Errorf("resolve the assignee's role: %w", err)
	}
	user, err := u.deps.Stores.Users.GetByID(ctx, userID)
	if err == nil && user.Role == auth.RoleAdmin {
		return nil
	}
	return ErrAssigneeNotMember
}
