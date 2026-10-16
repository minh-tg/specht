//go:build integration

package repo

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/port"
)

func (s *deleteScenario) recordIntroduced(t *testing.T, reportID string, findingIDs ...string) {
	t.Helper()
	entries := make([]port.IntroducedFindingEntry, len(findingIDs))
	for i, id := range findingIDs {
		entries[i] = port.IntroducedFindingEntry{FindingID: id, ChangeType: "new"}
	}
	require.NoError(t, s.stores.Findings.RecordReportIntroducedFindings(s.ctx, reportID, nil, entries))
}

func candidateIDs(candidates []port.GateCandidate) []string {
	ids := make([]string, len(candidates))
	for i, c := range candidates {
		ids[i] = c.ID
	}
	return ids
}

// The introduced-only gate lists the findings a report introduced, and the
// query itself must keep them inside the caller's project: a report id from
// another project, or a report whose introduced rows name a foreign finding,
// must never return that other project's findings, whatever the caller above
// checked.
func TestListIntroducedGateCandidates_StaysInsideTheProject(t *testing.T) {
	s, cleanup := newDeleteScenario(t)
	defer cleanup()

	other, err := s.stores.Projects.Create(s.ctx, port.CreateProjectInput{
		Slug: "other", Name: "Other", DeploymentThreshold: "high", Settings: []byte("{}"),
	})
	require.NoError(t, err)
	foreign := &deleteScenario{ctx: s.ctx, pool: s.pool, stores: s.stores, projectID: other.ID}
	foreignFinding := foreign.finding(t, "foreign-only")
	foreignReport := foreign.report(t, "ccccccc", 12*time.Hour)
	foreign.occurrence(t, foreignFinding, foreignReport)
	foreign.recordIntroduced(t, foreignReport, foreignFinding)

	// Report B of the scenario introduced onlyB, in the scenario's project.
	s.recordIntroduced(t, s.reportB, s.onlyB)

	t.Run("the project's own report lists its findings", func(t *testing.T) {
		got, err := s.stores.Findings.ListIntroducedGateCandidates(s.ctx, s.projectID, s.reportB, 0)
		require.NoError(t, err)
		assert.Equal(t, []string{s.onlyB}, candidateIDs(got))
	})

	t.Run("a report of another project lists nothing", func(t *testing.T) {
		got, err := s.stores.Findings.ListIntroducedGateCandidates(s.ctx, other.ID, s.reportB, 0)
		require.NoError(t, err)
		assert.Empty(t, candidateIDs(got), "the finding belongs to another project than the one asked for")

		got, err = s.stores.Findings.ListIntroducedGateCandidates(s.ctx, s.projectID, foreignReport, 0)
		require.NoError(t, err)
		assert.Empty(t, candidateIDs(got), "the finding belongs to another project than the one asked for")
	})

	t.Run("an introduced row naming a foreign finding is not listed", func(t *testing.T) {
		// A report row that points at another project's finding must not
		// leak it into this project's gate answer.
		s.exec(t, `INSERT INTO report_introduced_findings (report_id, finding_id, change_type) VALUES ($1, $2, 'new')`,
			s.reportB, foreignFinding)

		got, err := s.stores.Findings.ListIntroducedGateCandidates(s.ctx, s.projectID, s.reportB, 0)
		require.NoError(t, err)
		assert.Equal(t, []string{s.onlyB}, candidateIDs(got))
	})
}
