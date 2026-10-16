package usecase

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/port"
)

// Environment, target and artifact rows belong to the report that names them.
// An ingest that fails before the report row exists must not have written any.
func TestIngestReport_FailureBeforeTheReportRowLeavesNoContextRows(t *testing.T) {
	uc, _, rr := autofixHarness(t, "")
	var ensured, targets, artifacts int
	uc.deps.Stores.Environments = &mockEnvironmentRepo{ensureFn: func(context.Context, string, string, string, bool, string) (port.Environment, error) {
		ensured++
		return port.Environment{ID: "env-1"}, nil
	}}
	tr, ar := stubTargetRepo(), stubArtifactRepo()
	upsertTarget, upsertArtifact := tr.upsertFn, ar.upsertFn
	tr.upsertFn = func(ctx context.Context, p, n, k, l, o string) (port.Target, error) {
		targets++
		return upsertTarget(ctx, p, n, k, l, o)
	}
	ar.upsertFn = func(ctx context.Context, in port.ArtifactInput) (port.Artifact, error) {
		artifacts++
		return upsertArtifact(ctx, in)
	}
	uc.deps.Stores.Targets, uc.deps.Stores.Artifacts = tr, ar
	rr.byCommitFn = func(context.Context, string, string, string) (port.CompletedReport, error) {
		return port.CompletedReport{}, errors.New("database unavailable")
	}

	_, err := uc.IngestReport(context.Background(), IngestReportInput{
		ProjectSlug: "my-app", Scanner: "trivy", RawData: json.RawMessage(`{"a":1}`),
		Environment: "production", ArtifactName: "api", BaseRevision: "abc1234",
	})

	require.Error(t, err)
	assert.Zero(t, ensured, "no environment row")
	assert.Zero(t, targets, "no target row")
	assert.Zero(t, artifacts, "no artifact row")
}
