package usecase

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
)

var (
	ErrProjectAccessDenied = errors.New("project access denied")
	ErrInvalidFindingID    = errors.New("invalid finding id")
	// ErrInvalidID is returned when a UUID parameter is malformed.
	// Handlers map it to 400.
	ErrInvalidID = errors.New("invalid id")
)

// validID parses a UUID parameter, returning ErrInvalidID instead of a
// driver-specific parse error so handlers answer 400, not 500.
func validID(id string) (string, error) {
	if _, err := uuid.Parse(id); err != nil {
		return "", ErrInvalidID
	}
	return id, nil
}

func (u *Usecases) findingWithProjectAccess(ctx context.Context, findingID uuid.UUID) (port.Finding, error) {
	if u.deps.Stores == nil || u.deps.Stores.Findings == nil {
		return port.Finding{}, fmt.Errorf("check finding project: finding store unavailable")
	}

	finding, err := u.deps.Stores.Findings.GetByID(ctx, findingID.String())
	if err != nil {
		if errors.Is(err, port.ErrNotFound) {
			return port.Finding{}, ErrFindingNotFound
		}
		// Persistence failures (DB down, …) must not surface as not-found:
		// propagate the wrapped error so callers can log it and handlers map
		// it to a 500 instead of a misleading 404.
		return port.Finding{}, fmt.Errorf("check finding project: %w", err)
	}
	if err := u.checkFindingVisibility(ctx, finding.ProjectID); err != nil {
		return port.Finding{}, err
	}
	return finding, nil
}

func (u *Usecases) checkFindingProjectAccess(ctx context.Context, findingID uuid.UUID) error {
	_, err := u.findingWithProjectAccess(ctx, findingID)
	return err
}

func (u *Usecases) checkFindingRowsProjectAccess(ctx context.Context, findings []port.Finding) error {
	seen := make(map[string]bool, 2)
	for _, finding := range findings {
		if seen[finding.ProjectID] {
			continue
		}
		seen[finding.ProjectID] = true
		if err := u.checkFindingVisibility(ctx, finding.ProjectID); err != nil {
			return err
		}
	}
	return nil
}

// checkFindingVisibility masks inaccessible ID-addressed findings as missing.
// Role checks on a visible finding still return ErrProjectAccessDenied.
func (u *Usecases) checkFindingVisibility(ctx context.Context, projectID string) error {
	err := u.checkFindingProjectIDAccess(ctx, projectID)
	if auth.ContextIdentity(ctx) != nil && errors.Is(err, ErrProjectAccessDenied) {
		return ErrFindingNotFound
	}
	return err
}

// checkFindingProjectIDAccess enforces tenant isolation on finding-scoped
// reads and writes. Unauthenticated principals are denied outright.
// Project-scoped principals (API keys) must match the finding's project.
// Session users are authorized by membership: global admins bypass project
// scope, everyone else must hold direct or team-conferred membership
// (IsMemberEffective) for the finding's project. Membership-store failures
// deny access (fail closed) and are logged for operators.
func (u *Usecases) checkFindingProjectIDAccess(ctx context.Context, findingProjectID string) error {
	ident := auth.ContextIdentity(ctx)
	if ident == nil {
		return ErrProjectAccessDenied
	}
	if ident.IsAPIKey {
		if findingProjectID != ident.ProjectID {
			return ErrProjectAccessDenied
		}
		return nil
	}
	if ident.Role == auth.RoleAdmin {
		return nil
	}
	ok, err := u.deps.Stores.Projects.IsMemberEffective(ctx, findingProjectID, ident.UserID)
	if err != nil {
		slog.Error("check finding project: membership lookup failed", "error", err)
		return ErrProjectAccessDenied
	}
	if !ok {
		return ErrProjectAccessDenied
	}
	return nil
}

// requireProjectRole checks a minimum project permission using the effective
// membership role, including team-conferred membership. API keys must match the
// project and carry the operation's explicit scope. An empty apiKeyScope means
// no key scope covers the operation, so every key is refused.
func (u *Usecases) requireProjectRole(ctx context.Context, projectID, apiKeyScope string, allowedRoles ...string) error {
	ident := auth.ContextIdentity(ctx)
	if ident == nil {
		return ErrProjectAccessDenied
	}
	if ident.IsAPIKey {
		if apiKeyScope == "" || ident.ProjectID != projectID || !ident.HasScope(apiKeyScope) {
			return ErrProjectAccessDenied
		}
		return nil
	}
	if ident.Role == auth.RoleAdmin {
		return nil
	}
	role, err := u.deps.Stores.Projects.EffectiveRole(ctx, projectID, ident.UserID)
	if err != nil {
		if !errors.Is(err, port.ErrNotFound) {
			slog.Error("resolve project role: lookup failed", "error", err)
		}
		return ErrProjectAccessDenied
	}
	for _, allowed := range allowedRoles {
		if role == allowed {
			return nil
		}
	}
	return ErrProjectAccessDenied
}

// callerProjectRole resolves the effective project role for the session caller.
// Global admins automatically resolve to RoleAdmin. API keys are denied.
func (u *Usecases) callerProjectRole(ctx context.Context, projectID string) (string, error) {
	ident := auth.ContextIdentity(ctx)
	if ident == nil || ident.IsAPIKey {
		return "", ErrProjectAccessDenied
	}
	if ident.Role == auth.RoleAdmin {
		return auth.RoleAdmin, nil
	}
	role, err := u.deps.Stores.Projects.EffectiveRole(ctx, projectID, ident.UserID)
	if err != nil {
		if errors.Is(err, port.ErrNotFound) {
			return "", ErrProjectAccessDenied
		}
		return "", fmt.Errorf("resolve effective role: %w", err)
	}
	return role, nil
}

// projectBySlugOrDenied resolves a slug on a route that must not reveal whether
// a project exists. A missing project is ErrProjectAccessDenied, the answer a
// project the caller cannot see gets from the role check that follows. Global
// admins, who can see every project, get the lookup error.
func (u *Usecases) projectBySlugOrDenied(ctx context.Context, slug string) (port.Project, error) {
	p, err := u.deps.Stores.Projects.GetBySlug(ctx, slug)
	if err != nil {
		// A global admin may list every project, so for them a missing one is
		// plainly not found.
		if ident := auth.ContextIdentity(ctx); errors.Is(err, port.ErrNotFound) && (ident == nil || ident.IsAPIKey || ident.Role != auth.RoleAdmin) {
			return port.Project{}, ErrProjectAccessDenied
		}
		return port.Project{}, fmt.Errorf(errLookupProjectFormat, slug, err)
	}
	return p, nil
}

// requireDirectGrantCeiling keeps a role that comes from a team link from
// being copied into rows that outlive the link. Handing out manager or admin,
// by a member row, a team link or an invite, needs a direct project role at or
// above the role handed out: the caller's effective role may include team
// links, which the project's admins can revoke, and a row written on its
// strength would stay after they do. Member-level grants follow the effective
// role. Global admins are exempt.
func (u *Usecases) requireDirectGrantCeiling(ctx context.Context, projectID, role string) error {
	if auth.RoleRank(role) <= auth.RoleRank(auth.RoleMember) {
		return nil
	}
	ident := auth.ContextIdentity(ctx)
	if ident == nil || ident.IsAPIKey {
		return ErrProjectAccessDenied
	}
	if ident.Role == auth.RoleAdmin {
		return nil
	}
	direct, err := u.deps.Stores.Projects.GetMember(ctx, projectID, ident.UserID)
	switch {
	case errors.Is(err, port.ErrNotFound):
		return ErrProjectAccessDenied
	case err != nil:
		return fmt.Errorf("resolve direct project role: %w", err)
	}
	if auth.RoleRank(normalizeMemberRole(direct.Role)) < auth.RoleRank(role) {
		return ErrProjectAccessDenied
	}
	return nil
}

func (u *Usecases) requireProjectManager(ctx context.Context, projectID string) error {
	return u.requireProjectRole(ctx, projectID, "", auth.RoleAdmin, auth.RoleManager, auth.RoleEditor)
}

func (u *Usecases) requireProjectMember(ctx context.Context, projectID string) error {
	return u.requireProjectRole(ctx, projectID, auth.ScopeRead, auth.RoleAdmin, auth.RoleManager, auth.RoleMember, auth.RoleEditor, auth.RoleViewer)
}

func (u *Usecases) requireProjectIngest(ctx context.Context, projectID string) error {
	return u.requireProjectRole(ctx, projectID, auth.ScopeIngest, auth.RoleAdmin, auth.RoleManager, auth.RoleEditor)
}

// requireProjectAdminForWaiver gates direct waiver management (create,
// update, delete, toggle). Project managers manage waivers alongside admins.
func (u *Usecases) requireProjectAdminForWaiver(ctx context.Context, projectID string) error {
	return u.requireProjectManager(ctx, projectID)
}

func (u *Usecases) findingWithProjectEditor(ctx context.Context, findingID uuid.UUID) (port.Finding, error) {
	if u.deps.Stores == nil || u.deps.Stores.Findings == nil {
		return port.Finding{}, fmt.Errorf("check finding project role: finding store unavailable")
	}
	finding, err := u.deps.Stores.Findings.GetByID(ctx, findingID.String())
	if err != nil {
		if errors.Is(err, port.ErrNotFound) {
			return port.Finding{}, ErrFindingNotFound
		}
		return port.Finding{}, fmt.Errorf("check finding project role: %w", err)
	}
	if err := u.checkFindingVisibility(ctx, finding.ProjectID); err != nil {
		return port.Finding{}, err
	}
	if err := u.requireProjectManager(ctx, finding.ProjectID); err != nil {
		return port.Finding{}, err
	}
	return finding, nil
}

func (u *Usecases) checkFindingProjectEditor(ctx context.Context, findingID uuid.UUID) error {
	_, err := u.findingWithProjectEditor(ctx, findingID)
	return err
}

func (u *Usecases) checkFindingRowsProjectEditor(ctx context.Context, findings []port.Finding) error {
	if err := u.checkFindingRowsProjectAccess(ctx, findings); err != nil {
		return err
	}
	seen := make(map[string]bool, 2)
	for _, finding := range findings {
		if seen[finding.ProjectID] {
			continue
		}
		seen[finding.ProjectID] = true
		if err := u.requireProjectManager(ctx, finding.ProjectID); err != nil {
			return err
		}
	}
	return nil
}
