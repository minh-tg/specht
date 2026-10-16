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

// memberWriteError maps the store's last-admin refusal, raised under the
// project lock, to the usecase error. Refusals the checks run under that lock
// return pass through unchanged, and anything else is wrapped with the
// operation name.
func memberWriteError(op string, err error) error {
	switch {
	case errors.Is(err, port.ErrLastAdmin):
		return ErrLastAdminForbidden
	case errors.Is(err, ErrProjectAccessDenied), errors.Is(err, ErrMemberNotFound):
		return err
	}
	return fmt.Errorf("%s: %w", op, err)
}

// validateMemberRoleUpdate ensures non-admins do not modify peers or superiors.
// It is pure so it can run inside the store's membership lock, on the role the
// target holds once the lock is held. The last-admin rule is the store's.
func validateMemberRoleUpdate(callerRole, existingRole string) error {
	if auth.RoleRank(callerRole) < auth.RoleRank(auth.RoleAdmin) && auth.RoleRank(existingRole) >= auth.RoleRank(callerRole) {
		return ErrProjectAccessDenied
	}
	return nil
}

// canRemoveMember verifies authority when removing a project member, judged
// like validateMemberRoleUpdate. The last-admin rule is the store's.
func canRemoveMember(callerRole, targetRole string) error {
	if auth.RoleRank(callerRole) < auth.RoleRank(auth.RoleManager) {
		return ErrProjectAccessDenied
	}
	if auth.RoleRank(callerRole) < auth.RoleRank(auth.RoleAdmin) && auth.RoleRank(targetRole) >= auth.RoleRank(callerRole) {
		return ErrProjectAccessDenied
	}
	return nil
}

// memberEmail checks and normalizes an address typed into an add-member form.
func memberEmail(email string) (string, error) {
	email = strings.TrimSpace(email)
	if checkEmailLength(email) != nil {
		return "", ErrInvalidMemberEmail
	}
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
	if err := u.requireDirectGrantCeiling(ctx, p.ID, role); err != nil {
		return nil, err
	}

	userID, err := resolveUser(ctx)
	if err != nil {
		return nil, err
	}

	// The peer rule is judged by the store under its membership lock, on the
	// role the target holds then. Judged here on an earlier read, a concurrent
	// promotion could be overwritten by a manager's stale check.
	m, err := u.deps.Stores.Projects.UpsertMemberChecked(ctx, p.ID, userID, role, func(existing *port.ProjectMember) error {
		if existing == nil {
			return nil
		}
		return validateMemberRoleUpdate(callerRole, normalizeMemberRole(existing.Role))
	})
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

	selfExit := ident.UserID == userID
	var callerRole string
	if !selfExit {
		callerRole, err = u.callerProjectRole(ctx, p.ID)
		if err != nil {
			return err
		}
		if auth.RoleRank(callerRole) < auth.RoleRank(auth.RoleManager) {
			return ErrProjectAccessDenied
		}
	}

	// As in addProjectMember, the store judges the target's role under its lock.
	err = u.deps.Stores.Projects.DeleteMemberChecked(ctx, p.ID, userID, func(existing *port.ProjectMember) error {
		if existing == nil {
			return ErrMemberNotFound
		}
		if selfExit {
			return nil
		}
		return canRemoveMember(callerRole, normalizeMemberRole(existing.Role))
	})
	if err != nil {
		return memberWriteError("delete project member", err)
	}
	return nil
}

// IsProjectMember reports whether a user belongs to a project. It exists so
// HTTP-layer guards can enforce membership without reaching into stores.
func (u *Usecases) IsProjectMember(ctx context.Context, projectID, userID string) (bool, error) {
	return u.deps.Stores.Projects.IsMemberEffective(ctx, projectID, userID)
}
