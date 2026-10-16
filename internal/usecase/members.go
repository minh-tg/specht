package usecase

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"strings"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
)

var (
	ErrLastAdminForbidden = errors.New("cannot remove or demote the last project admin")
	ErrMemberNotFound     = errors.New("project member not found")
	// ErrInvalidMemberRole is returned when a requested role is outside the
	// project role vocabulary. Handlers map it to 400.
	ErrInvalidMemberRole = errors.New("invalid member role")
	// ErrMemberUserNotFound is returned when the user to grant access does
	// not exist. Handlers map it to 404.
	ErrMemberUserNotFound = errors.New("user not found")
	// ErrInvalidMemberEmail is returned when an address given to add a member
	// is not a plain email address. Handlers map it to 400.
	ErrInvalidMemberEmail = errors.New("invalid email address")
)

// ProjectMemberResponse is the API representation of a project membership.
type ProjectMemberResponse struct {
	ProjectID string `json:"project_id"`
	UserID    string `json:"user_id"`
	Role      string `json:"role"`
	CreatedAt string `json:"created_at"`
	// Email and DisplayName say who the member is. They are filled for a signed-in person only: a
	// project API key can read the roster, and a key sitting in a CI log should not leak addresses.
	Email       string `json:"email,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
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
	ident := auth.ContextIdentity(ctx)
	named := ident != nil && !ident.IsAPIKey
	resp := make([]ProjectMemberResponse, len(members))
	for i, m := range members {
		resp[i] = ProjectMemberResponse{
			ProjectID: m.ProjectID,
			UserID:    m.UserID,
			Role:      normalizeMemberRole(m.Role),
			CreatedAt: m.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		}
		if named {
			resp[i].Email = m.Email
			resp[i].DisplayName = m.DisplayName
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

// memberEmail checks and normalizes an address typed into an add-member form.
func memberEmail(email string) (string, error) {
	email = strings.TrimSpace(email)
	addr, err := mail.ParseAddress(email)
	if err != nil || addr.Address != email {
		return "", ErrInvalidMemberEmail
	}
	normalized := auth.NormalizeEmail(email)
	if normalized == "" {
		return "", ErrInvalidMemberEmail
	}
	return normalized, nil
}

// userByEmail finds the account behind an address. A missing account is
// ErrMemberUserNotFound, the same answer an unknown user id gets, so the
// response does not depend on how the caller named the person. Callers run it
// only after their permission checks pass.
func (u *Usecases) userByEmail(ctx context.Context, email string) (port.User, error) {
	user, err := u.deps.Stores.Users.GetByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, port.ErrNotFound) {
			return port.User{}, ErrMemberUserNotFound
		}
		return port.User{}, fmt.Errorf("lookup user by email: %w", err)
	}
	// The seeded system account acts for things with no person behind them. Nobody is added to a
	// project or team as it, and it answers like an address with no account.
	if isSystemAccount(user.Email) {
		return port.User{}, ErrMemberUserNotFound
	}
	return user, nil
}

// AddProjectMember grants a user a role on a project (upsert) subject to
// delegation boundaries and the last-admin invariant.
func (u *Usecases) AddProjectMember(ctx context.Context, projectSlug, userID, role string) (*ProjectMemberResponse, error) {
	if _, err := validID(userID); err != nil {
		return nil, err
	}
	return u.addProjectMember(ctx, projectSlug, role, func(context.Context) (string, error) { return userID, nil })
}

// AddProjectMemberByEmail grants the account behind an address a role on a
// project. It applies the same rules as AddProjectMember and looks the address
// up only once the caller is known to be allowed to add members.
func (u *Usecases) AddProjectMemberByEmail(ctx context.Context, projectSlug, email, role string) (*ProjectMemberResponse, error) {
	email, err := memberEmail(email)
	if err != nil {
		return nil, err
	}
	return u.addProjectMember(ctx, projectSlug, role, func(ctx context.Context) (string, error) {
		user, err := u.userByEmail(ctx, email)
		return user.ID, err
	})
}

func (u *Usecases) addProjectMember(ctx context.Context, projectSlug, role string, resolveUser func(context.Context) (string, error)) (*ProjectMemberResponse, error) {
	if !memberRoles[role] {
		return nil, fmt.Errorf("%w %q: must be admin, manager, or member", ErrInvalidMemberRole, role)
	}
	role = normalizeMemberRole(role)
	p, err := u.deps.Stores.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		if errors.Is(err, port.ErrNotFound) {
			// Indistinguishable from having no access, so a caller cannot
			// probe which project slugs exist.
			return nil, ErrProjectAccessDenied
		}
		return nil, fmt.Errorf("lookup project: %w", err)
	}

	callerRole, err := u.callerProjectRole(ctx, p.ID)
	if err != nil {
		return nil, err
	}
	if auth.RoleRank(callerRole) < auth.RoleRank(auth.RoleManager) || auth.RoleRank(role) > auth.RoleRank(callerRole) {
		return nil, ErrProjectAccessDenied
	}

	userID, err := resolveUser(ctx)
	if err != nil {
		return nil, err
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
		if errors.Is(err, port.ErrNotFound) {
			return nil, ErrMemberUserNotFound
		}
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
	if _, err := validID(userID); err != nil {
		return err
	}
	p, err := u.deps.Stores.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		if errors.Is(err, port.ErrNotFound) {
			return ErrProjectAccessDenied
		}
		return fmt.Errorf("lookup project: %w", err)
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
