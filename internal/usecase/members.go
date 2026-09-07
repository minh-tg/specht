package usecase

import (
	"context"
	"fmt"

	"github.com/xMinhx/specht/internal/auth"
)

// ProjectMemberResponse is the API representation of a project membership.
type ProjectMemberResponse struct {
	ProjectID string `json:"project_id"`
	UserID    string `json:"user_id"`
	Role      string `json:"role"`
	CreatedAt string `json:"created_at"`
}

// memberRoles is the allowed project_members.role vocabulary (migration
// 000002 CHECK constraint). AddProjectMember rejects anything else.
var memberRoles = map[string]bool{
	auth.RoleAdmin:  true,
	auth.RoleEditor: true,
	auth.RoleViewer: true,
}

// requireProjectAdmin reports whether the caller's identity may manage the
// project's membership: global admins, or admin-members of the project.
func (u *Usecases) requireProjectAdmin(ctx context.Context, projectID string) error {
	ident := auth.ContextIdentity(ctx)
	if ident == nil {
		return ErrProjectAccessDenied
	}
	if !ident.IsAPIKey && ident.Role == auth.RoleAdmin {
		return nil
	}
	// API keys never manage membership; non-admin session users must hold
	// an admin membership row.
	if ident.IsAPIKey {
		return ErrProjectAccessDenied
	}
	members, err := u.deps.Stores.Projects.ListMembers(ctx, projectID)
	if err != nil {
		return fmt.Errorf("list members: %w", err)
	}
	for _, m := range members {
		if m.UserID == ident.UserID && m.Role == auth.RoleAdmin {
			return nil
		}
	}
	return ErrProjectAccessDenied
}

// ListProjectMembers returns the membership roster for a project slug.
func (u *Usecases) ListProjectMembers(ctx context.Context, projectSlug string) ([]ProjectMemberResponse, error) {
	p, err := u.deps.Stores.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		return nil, fmt.Errorf("project not found: %w", err)
	}
	if err := u.requireProjectAdmin(ctx, p.ID); err != nil {
		return nil, err
	}
	members, err := u.deps.Stores.Projects.ListMembers(ctx, p.ID)
	if err != nil {
		return nil, fmt.Errorf("list members: %w", err)
	}
	resp := make([]ProjectMemberResponse, len(members))
	for i, m := range members {
		resp[i] = ProjectMemberResponse{
			ProjectID: m.ProjectID,
			UserID:    m.UserID,
			Role:      m.Role,
			CreatedAt: m.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		}
	}
	return resp, nil
}

// AddProjectMember grants a user a role on a project (upsert).
func (u *Usecases) AddProjectMember(ctx context.Context, projectSlug, userID, role string) (*ProjectMemberResponse, error) {
	if !memberRoles[role] {
		return nil, fmt.Errorf("invalid member role %q: must be admin, editor, or viewer", role)
	}
	p, err := u.deps.Stores.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		return nil, fmt.Errorf("project not found: %w", err)
	}
	if err := u.requireProjectAdmin(ctx, p.ID); err != nil {
		return nil, err
	}
	m, err := u.deps.Stores.Projects.UpsertMember(ctx, p.ID, userID, role)
	if err != nil {
		return nil, fmt.Errorf("add member: %w", err)
	}
	resp := &ProjectMemberResponse{
		ProjectID: m.ProjectID,
		UserID:    m.UserID,
		Role:      m.Role,
		CreatedAt: m.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}
	return resp, nil
}

// IsProjectMember reports whether a user belongs to a project. It exists so
// HTTP-layer guards can enforce membership without reaching into stores.
func (u *Usecases) IsProjectMember(ctx context.Context, projectID, userID string) (bool, error) {
	return u.deps.Stores.Projects.IsMember(ctx, projectID, userID)
}
