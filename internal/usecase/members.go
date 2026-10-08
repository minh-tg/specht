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

// memberWriteError maps the store's last-admin refusal, raised under a project
// lock when another writer removed the second admin first, to the usecase
// error and wraps anything else with the operation name.
func memberWriteError(op string, err error) error {
	if errors.Is(err, port.ErrLastAdmin) {
		return ErrLastAdminForbidden
	}
	return fmt.Errorf("%s: %w", op, err)
}

// ensureNotLastAdmin verifies that the project retains at least one admin.
func (u *Usecases) ensureNotLastAdmin(ctx context.Context, projectID string) error {
	admins, err := u.deps.Stores.Projects.CountAdmins(ctx, projectID)
	if err != nil {
		return fmt.Errorf("count project admins: %w", err)
	}
	if admins <= 1 {
		return ErrLastAdminForbidden
	}
	return nil
}

// validateMemberRoleUpdate ensures non-admins do not modify peers/superiors and
// that demoting an admin does not violate the last-admin invariant.
func (u *Usecases) validateMemberRoleUpdate(ctx context.Context, projectID, callerRole, newRole, existingRole string) error {
	if auth.RoleRank(callerRole) < auth.RoleRank(auth.RoleAdmin) && auth.RoleRank(existingRole) >= auth.RoleRank(callerRole) {
		return ErrProjectAccessDenied
	}
	if existingRole == auth.RoleAdmin && newRole != auth.RoleAdmin {
		return u.ensureNotLastAdmin(ctx, projectID)
	}
	return nil
}

// canRemoveMember verifies authority and invariants when removing a project member.
func (u *Usecases) canRemoveMember(ctx context.Context, projectID, callerRole, targetRole string) error {
	if auth.RoleRank(callerRole) < auth.RoleRank(auth.RoleManager) {
		return ErrProjectAccessDenied
	}
	if auth.RoleRank(callerRole) < auth.RoleRank(auth.RoleAdmin) && auth.RoleRank(targetRole) >= auth.RoleRank(callerRole) {
		return ErrProjectAccessDenied
	}
	if targetRole == auth.RoleAdmin {
		return u.ensureNotLastAdmin(ctx, projectID)
	}
	return nil
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
	if auth.RoleRank(callerRole) < auth.RoleRank(auth.RoleManager) || auth.RoleRank(role) > auth.RoleRank(callerRole) {
		return nil, ErrProjectAccessDenied
	}

	// Check existing member status for peer-protection and last-admin invariant.
	existing, err := u.deps.Stores.Projects.GetMember(ctx, p.ID, userID)
	if err == nil {
		if err := u.validateMemberRoleUpdate(ctx, p.ID, callerRole, role, normalizeMemberRole(existing.Role)); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, port.ErrNotFound) {
		return nil, fmt.Errorf("lookup member: %w", err)
	}

	m, err := u.deps.Stores.Projects.UpsertMember(ctx, p.ID, userID, role)
	if err != nil {
		return nil, memberWriteError("add member", err)
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

	if ident.UserID == userID {
		if targetRole == auth.RoleAdmin {
			if err := u.ensureNotLastAdmin(ctx, p.ID); err != nil {
				return err
			}
		}
	} else {
		callerRole, err := u.callerProjectRole(ctx, p.ID)
		if err != nil {
			return err
		}
		if err := u.canRemoveMember(ctx, p.ID, callerRole, targetRole); err != nil {
			return err
		}
	}

	if err := u.deps.Stores.Projects.DeleteMember(ctx, p.ID, userID); err != nil {
		return memberWriteError("delete project member", err)
	}
	return nil
}

// IsProjectMember reports whether a user belongs to a project. It exists so
// HTTP-layer guards can enforce membership without reaching into stores.
func (u *Usecases) IsProjectMember(ctx context.Context, projectID, userID string) (bool, error) {
	return u.deps.Stores.Projects.IsMemberEffective(ctx, projectID, userID)
}
