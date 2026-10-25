package usecase

import (
	"context"
	"errors"
	"fmt"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
)

// ProjectPermissions says which actions the caller may take on a project. It
// is for display: the UI hides what the server would refuse. Every write
// path still checks the role itself.
type ProjectPermissions struct {
	// RequestWaiver is true for every project member.
	RequestWaiver bool `json:"request_waiver"`
	// ManageWaivers covers creating, editing, deleting and toggling waivers.
	ManageWaivers bool `json:"manage_waivers"`
	// ApproveWaivers covers approving and rejecting waiver requests.
	ApproveWaivers bool `json:"approve_waivers"`
	// ManageMembers covers adding and removing members, within the caller's
	// own role.
	ManageMembers bool `json:"manage_members"`
	// ManageCI covers the CI setup: project API keys.
	ManageCI bool `json:"manage_ci"`
	// Triage covers analysis state, assignment and reachability changes.
	Triage bool `json:"triage"`
	// UploadReports covers uploading scan reports by hand, which goes
	// through the same ingest check as CI.
	UploadReports bool `json:"upload_reports"`
}

// isManagerRole reports whether a project role carries manager rights.
// Legacy roles count as their modern equivalents: an editor is a manager.
func isManagerRole(role string) bool {
	return auth.RoleRank(normalizeMemberRole(role)) >= auth.RoleRank(auth.RoleManager)
}

// permissionsForRole derives the permissions of an effective project role
// from the same predicates the write paths use.
func permissionsForRole(role string) ProjectPermissions {
	manager := isManagerRole(role)
	return ProjectPermissions{
		RequestWaiver:  waiverRequesterRole(role),
		ManageWaivers:  manager,
		ApproveWaivers: waiverApproverRole(role),
		ManageMembers:  manager,
		ManageCI:       manager,
		Triage:         manager,
		UploadReports:  manager,
	}
}

// callerPermissions resolves the signed-in caller's effective role on a
// project and the permissions it carries. It returns an empty role for API
// keys, which never drive the UI.
func (u *Usecases) callerPermissions(ctx context.Context, projectID string) (string, *ProjectPermissions, error) {
	ident := auth.ContextIdentity(ctx)
	if ident == nil || ident.IsAPIKey {
		return "", nil, nil
	}
	role := auth.RoleAdmin
	if ident.Role != auth.RoleAdmin {
		var err error
		role, err = u.deps.Stores.Projects.EffectiveRole(ctx, projectID, ident.UserID)
		if err != nil {
			if !errors.Is(err, port.ErrNotFound) {
				return "", nil, fmt.Errorf("resolve effective role: %w", err)
			}
			return "", nil, nil
		}
		role = normalizeMemberRole(role)
	}
	perms := permissionsForRole(role)
	return role, &perms, nil
}
