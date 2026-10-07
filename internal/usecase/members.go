package usecase

import (
	"context"
	"errors"
	"fmt"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
)

var (
	ErrLastAdminForbidden = errors.New("cannot remove or demote the last project admin")
	ErrMemberNotFound     = errors.New("project member not found")
)

// ProjectMemberResponse is the API representation of a project membership.
type ProjectMemberResponse struct {
	ProjectID string `json:"project_id"`
	UserID    string `json:"user_id"`
	Role      string `json:"role"`
	CreatedAt string `json:"created_at"`
}

// memberRoles is the allowed project_members.role vocabulary.
var memberRoles = map[string]bool{
	auth.RoleAdmin:   true,
	auth.RoleManager: true,
	auth.RoleMember:  true,
	"editor":         true,
	"viewer":         true,
}

// normalizeMemberRole maps legacy roles to modern equivalents.
func normalizeMemberRole(role string) string {
	switch role {
	case "editor":
		return auth.RoleManager
	case "viewer":
		return auth.RoleMember
	default:
		return role
	}
}

// requireProjectAdmin reports whether the caller's identity may manage the
// project's administration: global admins, or admin-members of the project.
func (u *Usecases) requireProjectAdmin(ctx context.Context, projectID string) error {
	ident := auth.ContextIdentity(ctx)
	if ident == nil || ident.IsAPIKey {
		return ErrProjectAccessDenied
	}
	if ident.Role == auth.RoleAdmin {
		return nil
	}
	role, err := u.deps.Stores.Projects.EffectiveRole(ctx, projectID, ident.UserID)
	if err != nil {
		if errors.Is(err, port.ErrNotFound) {
			return ErrProjectAccessDenied
		}
		return fmt.Errorf("resolve effective role: %w", err)
	}
	if role != auth.RoleAdmin {
		return ErrProjectAccessDenied
	}
	return nil
}

// ListProjectMembers returns the membership roster for a project slug.
// Accessible to project members, managers, and admins.
func (u *Usecases) ListProjectMembers(ctx context.Context, projectSlug string) ([]ProjectMemberResponse, error) {
	p, err := u.deps.Stores.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		return nil, fmt.Errorf("project not found: %w", err)
	}
	if err := u.requireProjectMember(ctx, p.ID); err != nil {
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
			Role:      normalizeMemberRole(m.Role),
			CreatedAt: m.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		}
	}
	return resp, nil
}

// AddProjectMember grants a user a role on a project (upsert) subject to
// delegation boundaries and the last-admin invariant.
func (u *Usecases) AddProjectMember(ctx context.Context, projectSlug, userID, role string) (*ProjectMemberResponse, error) {
	if !memberRoles[role] {
		return nil, fmt.Errorf("invalid member role %q: must be admin, manager, or member", role)
	}
	role = normalizeMemberRole(role)
	p, err := u.deps.Stores.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		return nil, fmt.Errorf("project not found: %w", err)
	}

	callerRole, err := u.callerProjectRole(ctx, p.ID)
	if err != nil {
		return nil, err
	}
	// Caller must be at least Manager.
	if auth.RoleRank(callerRole) < auth.RoleRank(auth.RoleManager) {
		return nil, ErrProjectAccessDenied
	}
	// Delegation ceiling: caller cannot grant a role higher than their own rank.
	if auth.RoleRank(role) > auth.RoleRank(callerRole) {
		return nil, ErrProjectAccessDenied
	}

	// Check existing member status for peer-protection and last-admin invariant.
	existing, err := u.deps.Stores.Projects.GetMember(ctx, p.ID, userID)
	if err == nil {
		existingRole := normalizeMemberRole(existing.Role)
		// Peer protection: non-admins cannot modify someone of equal or higher rank.
		if auth.RoleRank(callerRole) < auth.RoleRank(auth.RoleAdmin) {
			if auth.RoleRank(existingRole) >= auth.RoleRank(callerRole) {
				return nil, ErrProjectAccessDenied
			}
		}
		// Last admin invariant: demoting an admin requires another admin to exist.
		if existingRole == auth.RoleAdmin && role != auth.RoleAdmin {
			admins, err := u.deps.Stores.Projects.CountAdmins(ctx, p.ID)
			if err != nil {
				return nil, fmt.Errorf("count project admins: %w", err)
			}
			if admins <= 1 {
				return nil, ErrLastAdminForbidden
			}
		}
	} else if !errors.Is(err, port.ErrNotFound) {
		return nil, fmt.Errorf("lookup member: %w", err)
	}

	m, err := u.deps.Stores.Projects.UpsertMember(ctx, p.ID, userID, role)
	if err != nil {
		return nil, fmt.Errorf("add member: %w", err)
	}
	resp := &ProjectMemberResponse{
		ProjectID: m.ProjectID,
		UserID:    m.UserID,
		Role:      normalizeMemberRole(m.Role),
		CreatedAt: m.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}
	return resp, nil
}

// RemoveProjectMember removes a user from a project or allows self-exit, subject
// to delegation boundaries and the last-admin invariant.
func (u *Usecases) RemoveProjectMember(ctx context.Context, projectSlug, userID string) error {
	ident := auth.ContextIdentity(ctx)
	if ident == nil || ident.IsAPIKey {
		return ErrProjectAccessDenied
	}
	p, err := u.deps.Stores.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		return fmt.Errorf("project not found: %w", err)
	}

	target, err := u.deps.Stores.Projects.GetMember(ctx, p.ID, userID)
	if err != nil {
		if errors.Is(err, port.ErrNotFound) {
			return ErrMemberNotFound
		}
		return fmt.Errorf("lookup member: %w", err)
	}
	targetRole := normalizeMemberRole(target.Role)

	isSelf := ident.UserID == userID
	if isSelf {
		// Self-removal: allowed for all roles, except the last direct admin.
		if targetRole == auth.RoleAdmin {
			admins, err := u.deps.Stores.Projects.CountAdmins(ctx, p.ID)
			if err != nil {
				return fmt.Errorf("count project admins: %w", err)
			}
			if admins <= 1 {
				return ErrLastAdminForbidden
			}
		}
	} else {
		// Removing someone else requires Manager+ permissions.
		callerRole, err := u.callerProjectRole(ctx, p.ID)
		if err != nil {
			return err
		}
		if auth.RoleRank(callerRole) < auth.RoleRank(auth.RoleManager) {
			return ErrProjectAccessDenied
		}
		// Peer protection: non-admins cannot remove someone of equal or higher rank.
		if auth.RoleRank(callerRole) < auth.RoleRank(auth.RoleAdmin) {
			if auth.RoleRank(targetRole) >= auth.RoleRank(callerRole) {
				return ErrProjectAccessDenied
			}
		}
		// Last admin invariant: removing an admin requires another admin to exist.
		if targetRole == auth.RoleAdmin {
			admins, err := u.deps.Stores.Projects.CountAdmins(ctx, p.ID)
			if err != nil {
				return fmt.Errorf("count project admins: %w", err)
			}
			if admins <= 1 {
				return ErrLastAdminForbidden
			}
		}
	}

	if err := u.deps.Stores.Projects.DeleteMember(ctx, p.ID, userID); err != nil {
		return fmt.Errorf("delete project member: %w", err)
	}
	return nil
}

// IsProjectMember reports whether a user belongs to a project. It exists so
// HTTP-layer guards can enforce membership without reaching into stores.
func (u *Usecases) IsProjectMember(ctx context.Context, projectID, userID string) (bool, error) {
	return u.deps.Stores.Projects.IsMemberEffective(ctx, projectID, userID)
}
