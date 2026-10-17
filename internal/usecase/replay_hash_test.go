package usecase

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/domain"
	"github.com/minh-tg/specht/internal/parser"
	"github.com/minh-tg/specht/internal/port"
	"github.com/minh-tg/specht/internal/scanner"
)

const replayTrivyDoc = `{"SchemaVersion":2,"ArtifactName":"repo","ArtifactType":"filesystem","Results":[{"Target":"./app/.env","Class":"secret","Secrets":[{"RuleID":"aws-access-key-id","Category":"AWS","Severity":"CRITICAL","Title":"AWS Access Key ID","Match":"AWS_KEY=AKIAFIRSTSECRET0001"}]}]}`

// replayIndex stands in for the completed-report index in the database. A
// completed report is found by its raw hash, commit and scope, and by nothing
// else. created keeps every report row the ingest wrote.
type replayIndex struct {
	reports map[string]string
	created []port.CreateReportInput
}

// newReplayHarness ingests through the real parsers and redactors, so the
// stored form is the one a production ingest writes.
func newReplayHarness(t *testing.T) (*Usecases, *replayIndex) {
	t.Helper()
	uc, fr, rr := autofixHarness(t, domain.CompletenessComplete)
	fr.listIntroducedByFn = func(context.Context, string, string) ([]port.Finding, error) { return nil, nil }
	reg := scanner.NewRegistry()
	for _, s := range parser.Builtins() {
		require.NoError(t, reg.Register(s))
	}
	uc.deps.Registry = reg

	idx := &replayIndex{reports: map[string]string{}}
	indexKey := func(rawHash, commit, scope string) string {
		return strings.Join([]string{rawHash, commit, scope}, "\x00")
	}
	rr.createFn = func(ctx context.Context, arg port.CreateReportInput) (port.Report, error) {
		var commit string
		if arg.CommitSha != nil {
			commit = *arg.CommitSha
		}
		r := makeReport()
		r.ID = fmt.Sprintf("report-%d", len(idx.created)+1)
		idx.created = append(idx.created, arg)
		idx.reports[indexKey(arg.RawReportHash, commit, arg.ScanScopeHash)] = r.ID
		return r, nil
	}
	rr.findCompletedByReplayKeyFn = func(ctx context.Context, projectID, rawHash, commit, scopeHash string) (string, error) {
		if id, ok := idx.reports[indexKey(rawHash, commit, scopeHash)]; ok {
			return id, nil
		}
		return "", port.ErrNotFound
	}
	rr.getByIDFn = func(ctx context.Context, id string) (port.Report, error) {
		r := makeReport()
		r.ID = id
		return r, nil
	}
	return uc, idx
}

func ingestTrivyBody(t *testing.T, uc *Usecases, body string) *IngestReportOutput {
	t.Helper()
	out, err := uc.IngestReport(context.Background(), IngestReportInput{
		ProjectSlug: "my-app", Scanner: "trivy", RawData: json.RawMessage(body), CommitSha: "same-commit",
	})
	require.NoError(t, err)
	return out
}

// A whitespace run is gone once the JSON is re-encoded, so the stored form of
// both bodies is the same bytes. The bodies still differ, so both are reports.
func TestIngestReport_BodiesThatDifferOnlyInWhitespaceAreTwoReports(t *testing.T) {
	uc, idx := newReplayHarness(t)
	spaced := strings.Replace(replayTrivyDoc, `"SchemaVersion":2`, `"SchemaVersion":   2`, 1)
	require.NotEqual(t, replayTrivyDoc, spaced)

	first := ingestTrivyBody(t, uc, replayTrivyDoc)
	second := ingestTrivyBody(t, uc, spaced)

	require.Len(t, idx.created, 2, "both bodies are written")
	assert.Equal(t, string(idx.created[0].RawData), string(idx.created[1].RawData),
		"the stored forms collide, so only the hash over the original body keeps them apart")
	assert.False(t, first.Replayed)
	assert.False(t, second.Replayed, "a whitespace-only difference is not a replay")
	assert.NotEqual(t, first.ReportID, second.ReportID)
}

// Two secrets redact to the same marker, so their stored forms are the same
// bytes. The original bodies differ in the secret, so both are reports.
func TestIngestReport_BodiesThatDifferOnlyInARedactedValueAreTwoReports(t *testing.T) {
	uc, idx := newReplayHarness(t)
	rotated := strings.Replace(replayTrivyDoc, "AKIAFIRSTSECRET0001", "AKIASECONDSECRET0002", 1)

	first := ingestTrivyBody(t, uc, replayTrivyDoc)
	second := ingestTrivyBody(t, uc, rotated)

	require.Len(t, idx.created, 2, "both bodies are written")
	assert.Equal(t, string(idx.created[0].RawData), string(idx.created[1].RawData),
		"the stored forms collide: the secret is redacted in both")
	assert.NotContains(t, string(idx.created[1].RawData), "AKIASECONDSECRET0002")
	assert.False(t, second.Replayed, "a rotated secret is not a replay of the old report")
	assert.NotEqual(t, first.ReportID, second.ReportID)
}

// The same body posted again for the same commit and scope answers with the
// stored report and writes nothing new.
func TestIngestReport_TheSameBodyTwiceReplaysTheStoredReport(t *testing.T) {
	uc, idx := newReplayHarness(t)

	first := ingestTrivyBody(t, uc, replayTrivyDoc)
	second := ingestTrivyBody(t, uc, replayTrivyDoc)

	assert.False(t, first.Replayed)
	assert.True(t, second.Replayed)
	assert.Equal(t, first.ReportID, second.ReportID)
	assert.Len(t, idx.created, 1, "a replay writes no second report")
}
