package usecase

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
)

const readAccessWaiverID = "55555555-5555-5555-5555-555555555555"

// projectReaders lists every usecase that returns a project's data from a
// slug. Each must refuse a caller who is not a member of that project,
// whatever transport reached it.
func projectReaders(uc *Usecases, slug string) map[string]func(context.Context) error {
	return map[string]func(context.Context) error{
		"ListFindings": func(ctx context.Context) error {
			_, _, err := uc.ListFindings(ctx, slug, FindingFilter{}, 10, 0)
			return err
		},
		"ListReports": func(ctx context.Context) error {
			_, err := uc.ListReports(ctx, slug, 10, 0)
			return err
		},
		"ListEnvironments": func(ctx context.Context) error {
			_, err := uc.ListEnvironments(ctx, slug)
			return err
		},
		"ListTargets": func(ctx context.Context) error {
			_, err := uc.ListTargets(ctx, slug)
			return err
		},
		"ListArtifacts": func(ctx context.Context) error {
			_, err := uc.ListArtifacts(ctx, slug)
			return err
		},
		"GetProjectStats": func(ctx context.Context) error {
			_, err := uc.GetProjectStats(ctx, slug)
			return err
		},
		"GetAging": func(ctx context.Context) error {
			_, err := uc.GetAging(ctx, slug)
			return err
		},
		"GetGateStatus": func(ctx context.Context) error {
			_, err := uc.GetGateStatus(ctx, slug, 3)
			return err
		},
		"GetIntroducedGateStatus": func(ctx context.Context) error {
			_, err := uc.GetIntroducedGateStatus(ctx, slug, 3, "")
			return err
		},
		"PreviewPRCheck": func(ctx context.Context) error {
			_, err := uc.PreviewPRCheck(ctx, PRCheckPreviewInput{ProjectSlug: slug, CommitSha: "0123abcd"})
			return err
		},
		"EffectivePolicy": func(ctx context.Context) error {
			_, err := uc.EffectivePolicy(ctx, slug)
			return err
		},
		"ListWaivers": func(ctx context.Context) error {
			_, err := uc.ListWaivers(ctx, slug)
			return err
		},
		"GetWaiver": func(ctx context.Context) error {
			_, err := uc.GetWaiver(ctx, slug, readAccessWaiverID)
			return err
		},
		"ListWaiverEvents": func(ctx context.Context) error {
			_, err := uc.ListWaiverEvents(ctx, slug, readAccessWaiverID)
			return err
		},
	}
}

// denied reports whether the call was refused by the access check. A call
// that gets past the check runs into the unwired data stores, which panics or
// fails differently; either way it was not denied.
func denied(call func(context.Context) error, ctx context.Context) (refused bool) {
	defer func() {
		if recover() != nil {
			refused = false
		}
	}()
	return errors.Is(call(ctx), ErrProjectAccessDenied)
}

func readAccessUsecases(role string, roleErr error) (*Usecases, string) {
	project := makeProject(true)
	pr := &mockProjectRepo{
		getBySlugFn: func(context.Context, string) (port.Project, error) { return project, nil },
		effectiveRoleFn: func(context.Context, string, string) (string, error) {
			return role, roleErr
		},
	}
	return New(Deps{Stores: &port.Stores{Projects: pr}}), project.ID
}

func TestProjectReaders_RefuseCallersWhoAreNotMembers(t *testing.T) {
	const slug = "my-app"
	callers := []struct {
		name string
		ctx  func(projectID string) context.Context
		role string
		err  error
	}{
		{"no identity", func(string) context.Context { return context.Background() }, "", nil},
		{"session without membership", func(string) context.Context { return sessionCtx("u1", auth.RoleViewer) }, "", port.ErrNotFound},
		{"api key for another project", func(string) context.Context { return apiKeyCtx("u1", "99999999-9999-9999-9999-999999999999") }, "", nil},
	}
	for _, c := range callers {
		t.Run(c.name, func(t *testing.T) {
			uc, projectID := readAccessUsecases(c.role, c.err)
			for name, call := range projectReaders(uc, slug) {
				assert.True(t, denied(call, c.ctx(projectID)), "%s must refuse: %s", name, c.name)
			}
		})
	}
}

func TestProjectReaders_AdmitMembers(t *testing.T) {
	const slug = "my-app"
	uc, projectID := readAccessUsecases(auth.RoleMember, nil)
	callers := map[string]context.Context{
		"project member":        sessionCtx("u1", auth.RoleViewer),
		"global admin":          adminCtx(),
		"api key for a project": apiKeyCtx("u1", projectID),
	}
	for who, ctx := range callers {
		for name, call := range projectReaders(uc, slug) {
			assert.False(t, denied(call, ctx), "%s must admit a %s", name, who)
		}
	}
}
