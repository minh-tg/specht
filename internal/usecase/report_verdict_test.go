package usecase

import (
	"context"
	"testing"

	"github.com/minh-tg/specht/internal/port"
	"github.com/stretchr/testify/require"
)

func TestReportVerdictsRequireCompletedEvidence(t *testing.T) {
	for _, status := range []string{"processing", "failed", ""} {
		t.Run(status, func(t *testing.T) {
			pr, rr, fr := makeTestRepos()
			pr.getBySlugFn = func(context.Context, string) (port.Project, error) {
				return makeProject(true), nil
			}
			rr.getByIDFn = func(context.Context, string) (port.Report, error) {
				r := makeReport()
				r.Status = status
				return r, nil
			}
			uc := New(Deps{Stores: &port.Stores{
				Projects: pr, Reports: rr, Findings: fr, Waivers: &mockWaiverRepo{},
			}})
			_, err := uc.GetIntroducedGateStatus(adminCtx(), "my-app", 0, makeReport().ID)
			require.ErrorContains(t, err, "report has not completed")
			_, err = uc.PreviewPRCheck(adminCtx(), PRCheckPreviewInput{
				ProjectSlug: "my-app", CommitSha: prcheckCommit, ReportID: makeReport().ID,
			})
			require.ErrorContains(t, err, "report has not completed")
		})
	}
}
