package usecase

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/port"
)

// In changes_only mode the adapter fails a step only for a report that scans a change, and it learns
// that from change_report. A rerun of the same job replays the first report, so it has to say the
// same, or "Re-run failed jobs" turns a failing change into a passing one.
func TestIngestReport_ARerunAnswersChangeReportLikeTheFirstRun(t *testing.T) {
	main := "main"
	cases := map[string]struct {
		branch string
		want   bool
	}{
		"a push build of a feature branch": {"feat/y", true},
		"a build of the default branch":    {"main", false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			uc, idx := newReplayHarness(t)
			pr := uc.deps.Stores.Projects.(*mockProjectRepo)
			pr.getBySlugFn = func(context.Context, string) (port.Project, error) {
				p := makeProject(true)
				p.DefaultBranch = &main
				p.Settings = json.RawMessage(`{"policy":{"gate_mode":"changes_only"}}`)
				return p, nil
			}
			uc.deps.Stores.Reports.(*mockReportRepo).getByIDFn = func(_ context.Context, id string) (port.Report, error) {
				r := makeReport()
				r.ID = id
				// The report row keeps the branch the first upload named.
				r.Branch = idx.created[0].Branch
				r.BaseRevision = idx.created[0].BaseRevision
				return r, nil
			}
			ingest := func() *IngestReportOutput {
				out, err := uc.IngestReport(context.Background(), IngestReportInput{
					ProjectSlug: "my-app", Scanner: "trivy", RawData: json.RawMessage(replayTrivyDoc),
					CommitSha: "same-commit", Branch: tc.branch,
				})
				require.NoError(t, err)
				return out
			}

			first, rerun := ingest(), ingest()

			require.False(t, first.Replayed)
			require.True(t, rerun.Replayed)
			assert.True(t, first.ReportOnly, "changes_only reports instead of failing a push build")
			assert.Equal(t, tc.want, first.ChangeReport, "the first run")
			assert.Equal(t, first.ChangeReport, rerun.ChangeReport, "the rerun says the same")
			assert.Equal(t, first.ReportOnly, rerun.ReportOnly)
		})
	}
}
