package usecase

import (
	"context"
	"fmt"

	"golang.org/x/sync/errgroup"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
)

// summaryWorkers is how many projects ListProjectSummaries evaluates at once.
// Each project costs a gate evaluation and a dozen statistics queries, so an
// admin of a few hundred projects would wait for thousands of queries in a
// row. A small limit keeps most of the connection pool for other requests.
const summaryWorkers = 4

// ProjectSummary is one row of the project list: the project's gate and its
// statistics, the same values GET /projects/{slug}/gate (no query) and
// GET /projects/{slug}/stats return for it.
type ProjectSummary struct {
	Slug  string            `json:"slug"`
	Gate  *GateStatusOutput `json:"gate"`
	Stats *ProjectStats     `json:"stats"`
}

// ListProjectSummaries returns a summary for every project ListProjects shows
// the caller, in the same order. Each project's gate is evaluated once and
// feeds both the gate and the blocking numbers of the statistics, where the
// two per-project endpoints evaluate it once each. The projects come from the
// access filter, so there is no per-project slug lookup or role check.
func (u *Usecases) ListProjectSummaries(ctx context.Context) ([]ProjectSummary, error) {
	// The route checks the scope too. A key without read scope must not get
	// project data from here even if a route forgets to.
	if ident := auth.ContextIdentity(ctx); ident != nil && ident.IsAPIKey && !ident.HasScope(auth.ScopeRead) {
		return nil, ErrProjectAccessDenied
	}
	projects, err := u.visibleProjects(ctx)
	if err != nil {
		return nil, err
	}

	summaries := make([]ProjectSummary, len(projects))
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(summaryWorkers)
	for i, project := range projects {
		g.Go(func() error {
			summary, err := u.projectSummary(gctx, project)
			if err != nil {
				return fmt.Errorf("summary of %q: %w", project.Slug, err)
			}
			summaries[i] = summary
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	return summaries, nil
}

// projectSummary evaluates one project's gate once and builds its row from it.
func (u *Usecases) projectSummary(ctx context.Context, project port.Project) (ProjectSummary, error) {
	decision, policy, err := u.evaluateProjectGate(ctx, project, 0)
	if err != nil {
		return ProjectSummary{}, err
	}
	gateStatus, err := u.gateStatusFrom(ctx, project, decision, policy)
	if err != nil {
		return ProjectSummary{}, err
	}
	stats, err := u.projectStatsFrom(ctx, project, decision)
	if err != nil {
		return ProjectSummary{}, err
	}
	return ProjectSummary{Slug: project.Slug, Gate: gateStatus, Stats: stats}, nil
}
