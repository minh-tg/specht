//go:build e2e

package e2e

import (
	"context"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// TestE2E_WaiverUpdateAndDeleteAreAuditedAndKeepAnArchive: a waiver update and
// a waiver delete each leave an audit line naming the actor, the project and
// the waiver, and the delete keeps the waiver's identity and event trail in
// waiver_deletions instead of cascading it away.
func TestE2E_WaiverUpdateAndDeleteAreAuditedAndKeepAnArchive(t *testing.T) {
	slug := newProject(t, "waiver-audit")
	key := mintKey(t, slug)
	ingestFixture(t, slug, key, "high-medium.sarif.json")
	target := highFinding(t, slug)
	admin := request[profileEnvelope](t, http.MethodGet, "/api/v1/me", adminToken, nil, http.StatusOK)

	waiver := createWaiver(t, slug, "audited-waiver", target.ID, "")
	waiverPath := "/api/v1/projects/" + slug + "/waivers/" + waiver.ID

	request[waiverDetail](t, http.MethodPut, waiverPath, adminToken,
		map[string]string{"description": "changed"}, http.StatusOK)
	updated := auditLines(t, "waiver.update")
	require.NotEmpty(t, updated, "the update leaves an audit line")
	last := updated[len(updated)-1]
	require.Contains(t, last, "outcome=success")
	require.Contains(t, last, "principal_id="+admin.ID)
	require.Contains(t, last, "project="+slug)
	require.Contains(t, last, "target="+waiver.ID)

	status, _ := doJSON(t, http.MethodDelete, waiverPath, adminToken, nil)
	require.Equal(t, http.StatusNoContent, status)
	deleted := auditLines(t, "waiver.delete")
	require.NotEmpty(t, deleted, "the delete leaves an audit line")
	last = deleted[len(deleted)-1]
	require.Contains(t, last, "outcome=success")
	require.Contains(t, last, "principal_id="+admin.ID)
	require.Contains(t, last, "project="+slug)
	require.Contains(t, last, "target="+waiver.ID)

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	var deletedBy, name string
	var events int
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT deleted_by, snapshot->'waiver'->>'name', jsonb_array_length(snapshot->'events')
		  FROM waiver_deletions WHERE waiver_id = $1`, waiver.ID).Scan(&deletedBy, &name, &events))
	require.Equal(t, admin.ID, deletedBy)
	require.Equal(t, "audited-waiver", name)
	require.Equal(t, 2, events, "created and updated survive the delete")

	// The waiver itself is gone from the API and from the gate.
	status, _ = doJSON(t, http.MethodGet, waiverPath, adminToken, nil)
	require.Equal(t, http.StatusNotFound, status)
	require.True(t, getGate(t, slug, "").ThresholdBreached, "a deleted waiver no longer silences the gate")
}

type waiverScopeDetail struct {
	ID       string `json:"id"`
	Contexts []struct {
		EnvironmentID string `json:"environment_id"`
		TargetID      string `json:"target_id"`
		ArtifactID    string `json:"artifact_id"`
	} `json:"contexts"`
}

// TestE2E_WaiverContextReadsTheDocumentedKeys: a context written with the
// documented environment_id key keeps that environment. A context that names
// nothing it understands is refused, because it would cover every finding.
func TestE2E_WaiverContextReadsTheDocumentedKeys(t *testing.T) {
	slug := newProject(t, "waiver-ctx")
	key := mintKey(t, slug)
	ingestFixture(t, slug, key, "high.sarif.json")
	request[ingestResponse](t, http.MethodPost, "/api/v1/reports", key,
		ingestBodyWith(t, slug, "medium.sarif.json", map[string]any{"environment": "dev"}), http.StatusCreated)
	dev := findEnvironment(t, slug, "dev")

	created := request[waiverScopeDetail](t, http.MethodPost, "/api/v1/projects/"+slug+"/waivers", adminToken,
		map[string]any{
			"name":     "dev only",
			"contexts": []map[string]string{{"environment_id": dev.ID}},
		}, http.StatusCreated)
	detail := request[waiverScopeDetail](t, http.MethodGet,
		"/api/v1/projects/"+slug+"/waivers/"+created.ID, adminToken, nil, http.StatusOK)
	require.Len(t, detail.Contexts, 1)
	require.Equal(t, dev.ID, detail.Contexts[0].EnvironmentID, "the context keeps the environment it was given")
	require.True(t, getGate(t, slug, "").ThresholdBreached, "a dev waiver leaves a finding that has no environment blocking")

	for name, ctxs := range map[string][]map[string]string{
		"misspelled key": {{"env_id": dev.ID}},
		"empty context":  {{}},
	} {
		status, body := doJSON(t, http.MethodPost, "/api/v1/projects/"+slug+"/waivers", adminToken,
			map[string]any{"name": name, "contexts": ctxs})
		require.Equalf(t, http.StatusBadRequest, status, "%s: %s", name, body)
	}
}

// TestE2E_EnvironmentWaiverDoesNotCoverTheProductionFinding: a waiver scoped to
// dev covers a finding that only dev scans reported. Once a production scan
// has reported a finding, a later dev scan of the same code does not let the
// dev waiver cover it.
func TestE2E_EnvironmentWaiverDoesNotCoverTheProductionFinding(t *testing.T) {
	slug := newProject(t, "waiver-env")
	key := mintKey(t, slug)
	scan := func(fixture, environment, commit string) {
		request[ingestResponse](t, http.MethodPost, "/api/v1/reports", key,
			ingestBodyWith(t, slug, fixture, map[string]any{
				"environment": environment, "branch": "main", "commit_sha": commit,
			}), http.StatusCreated)
	}
	const sha = "cccccccccccccccccccccccccccccccccccccccc"

	// A dev-only scan creates the environment and the dev-only finding.
	scan("high-new.sarif.json", "dev", sha)
	dev := findEnvironment(t, slug, "dev")
	request[waiverScopeDetail](t, http.MethodPost, "/api/v1/projects/"+slug+"/waivers", adminToken,
		map[string]any{
			"name":     "dev noise",
			"contexts": []map[string]string{{"environment_id": dev.ID}},
		}, http.StatusCreated)
	require.False(t, getGate(t, slug, "").ThresholdBreached, "the dev waiver covers the finding only dev has seen")

	// Production reports another finding: the dev waiver does not cover it.
	scan("high.sarif.json", "production", sha)
	before := getGate(t, slug, "")
	require.True(t, before.ThresholdBreached, "the production finding is not waived")
	require.EqualValues(t, 1, before.BlockingCount)
	require.Equal(t, 1, before.WaivedCount)

	// The same code scanned in dev afterwards makes dev the newest scan of the
	// finding, but production still reports it.
	scan("high.sarif.json", "dev", sha)
	after := getGate(t, slug, "")
	require.True(t, after.ThresholdBreached, "a newer dev scan must not let the dev waiver cover the production finding")
	require.EqualValues(t, 1, after.BlockingCount)
	require.Equal(t, 1, after.WaivedCount)

	// The per-finding check agrees with the gate.
	production := after.BlockedBy[0]
	matched := request[checkMatchResponse](t, http.MethodPost,
		"/api/v1/projects/"+slug+"/waivers/check-match", adminToken,
		map[string]string{"finding_id": production}, http.StatusOK)
	require.False(t, matched.Matched)
}

// artifactIDByName returns the id of the project's artifact with that name.
func artifactIDByName(t *testing.T, slug, name string) string {
	t.Helper()
	rows := request[[]artifactRow](t, http.MethodGet, "/api/v1/projects/"+slug+"/artifacts", adminToken, nil, http.StatusOK)
	for _, a := range rows {
		if a.Name == name {
			return a.ID
		}
	}
	require.Failf(t, "artifact missing", "%q not among %d artifacts", name, len(rows))
	return ""
}

// findingBySeverity returns the project's only finding at that severity.
func findingBySeverity(t *testing.T, slug, severity string) findingResponse {
	t.Helper()
	var found []findingResponse
	for _, f := range listFindings(t, slug) {
		if f.CurrentSeverity == severity {
			found = append(found, f)
		}
	}
	require.Lenf(t, found, 1, "expected exactly one %s finding", severity)
	return found[0]
}

func waiverCheckMatch(t *testing.T, slug, findingID string) bool {
	t.Helper()
	return request[checkMatchResponse](t, http.MethodPost,
		"/api/v1/projects/"+slug+"/waivers/check-match", adminToken,
		map[string]string{"finding_id": findingID}, http.StatusOK).Matched
}

// scanArtifact uploads a fixture as a scan of one container image in one
// environment.
func scanArtifact(t *testing.T, slug, key, fixture, environment, artifact string) {
	t.Helper()
	request[ingestResponse](t, http.MethodPost, "/api/v1/reports", key,
		ingestBodyWith(t, slug, fixture, map[string]any{
			"environment": environment, "branch": "main", "commit_sha": baseSHA,
			"artifact_name": artifact, "artifact_type": "container_image",
		}), http.StatusCreated)
}

// TestE2E_ArtifactWaiverDoesNotCoverAnotherArtifactsFinding: a waiver scoped
// to the dev image covers a finding only that image reported. Once production
// has reported a finding on its own image, a later dev-image scan of the same
// code does not let the waiver cover it.
func TestE2E_ArtifactWaiverDoesNotCoverAnotherArtifactsFinding(t *testing.T) {
	slug := newProject(t, "waiver-artifact")
	key := mintKey(t, slug)
	scanArtifact(t, slug, key, "medium.sarif.json", "dev", "dev-img")
	devImg := artifactIDByName(t, slug, "dev-img")
	request[waiverScopeDetail](t, http.MethodPost, "/api/v1/projects/"+slug+"/waivers", adminToken,
		map[string]any{"name": "dev image", "contexts": []map[string]string{{"artifact_id": devImg}}}, http.StatusCreated)
	require.True(t, waiverCheckMatch(t, slug, findingBySeverity(t, slug, "medium").ID),
		"the waiver covers a finding only the dev image reported")

	scanArtifact(t, slug, key, "high.sarif.json", "production", "prod-img")
	require.True(t, getGate(t, slug, "").ThresholdBreached, "the production finding blocks")

	scanArtifact(t, slug, key, "high.sarif.json", "dev", "dev-img")
	after := getGate(t, slug, "")
	require.Truef(t, after.ThresholdBreached,
		"a dev-image scan must not let the dev-image waiver cover the production finding (waived=%d)", after.WaivedCount)
	require.EqualValues(t, 1, after.BlockingCount)
	require.Zero(t, after.WaivedCount)
	require.False(t, waiverCheckMatch(t, slug, after.BlockedBy[0]), "the per-finding check agrees with the gate")
}

// TestE2E_MixedWaiverContextsJudgeEachScanWhole: a waiver for {dev} and
// {production, batch-img} covers what dev and the production batch image
// report. A finding production reported on another image stays blocked after
// a dev scan of the same code: each scan's environment and artifact are
// matched against one context together.
func TestE2E_MixedWaiverContextsJudgeEachScanWhole(t *testing.T) {
	slug := newProject(t, "waiver-mixed")
	key := mintKey(t, slug)
	scanArtifact(t, slug, key, "medium.sarif.json", "dev", "dev-img")
	scanArtifact(t, slug, key, "medium.sarif.json", "production", "batch-img")
	dev := findEnvironment(t, slug, "dev")
	prod := findEnvironment(t, slug, "production")
	batch := artifactIDByName(t, slug, "batch-img")
	request[waiverScopeDetail](t, http.MethodPost, "/api/v1/projects/"+slug+"/waivers", adminToken,
		map[string]any{"name": "dev, and the production batch image", "contexts": []map[string]string{
			{"environment_id": dev.ID},
			{"environment_id": prod.ID, "artifact_id": batch},
		}}, http.StatusCreated)
	require.True(t, waiverCheckMatch(t, slug, findingBySeverity(t, slug, "medium").ID),
		"the waiver covers a finding dev and the production batch image reported")

	scanArtifact(t, slug, key, "high.sarif.json", "production", "web-img")
	require.True(t, getGate(t, slug, "").ThresholdBreached, "the web-img production finding is not covered")

	scanArtifact(t, slug, key, "high.sarif.json", "dev", "dev-img")
	after := getGate(t, slug, "")
	require.Truef(t, after.ThresholdBreached,
		"a dev scan must not let the waiver cover a finding production reported on web-img (blocking=%d waived=%d)",
		after.BlockingCount, after.WaivedCount)
	require.EqualValues(t, 1, after.BlockingCount)
	require.Zero(t, after.WaivedCount)
	require.False(t, waiverCheckMatch(t, slug, after.BlockedBy[0]), "the per-finding check agrees with the gate")
}

// TestE2E_WaiverScopeMustBelongToTheProject: creating or updating a waiver with
// a finding, environment, target or artifact id of another project answers the
// same 404 as an id that does not exist, and a malformed id answers 400. None
// of them answers 201 or 500, and nothing is stored.
func TestE2E_WaiverScopeMustBelongToTheProject(t *testing.T) {
	slug := newProject(t, "waiver-scope")
	other := newProject(t, "waiver-scope-other")
	ingestFixture(t, slug, mintKey(t, slug), "high.sarif.json")
	ownFinding := highFinding(t, slug)

	// The other project has a finding, an environment, a target and an artifact.
	ingestRaw(t, other, "trivy", "trivy-alpine-scan.json", map[string]any{
		"branch": "main", "commit_sha": baseSHA, "environment": "production",
		"artifact_name": "alpine:3.20", "artifact_version": "3.20.3", "artifact_type": "container_image",
		"owner": "github://minh/specht",
	})
	foreignFinding := listFindings(t, other)[0].ID
	foreignEnv := findEnvironment(t, other, "production").ID
	foreignArtifacts := request[[]artifactRow](t, http.MethodGet,
		"/api/v1/projects/"+other+"/artifacts", adminToken, nil, http.StatusOK)
	require.NotEmpty(t, foreignArtifacts)
	foreignArtifact, foreignTarget := foreignArtifacts[0].ID, foreignArtifacts[0].TargetID
	const missing = "00000000-0000-4000-8000-00000000dead"

	base := "/api/v1/projects/" + slug + "/waivers"
	own := createWaiver(t, slug, "own", ownFinding.ID, "")
	before := request[[]waiverScopeDetail](t, http.MethodGet, base, adminToken, nil, http.StatusOK)

	bodies := map[string]map[string]any{
		"foreign finding":     {"target_ids": []string{foreignFinding}},
		"missing finding":     {"target_ids": []string{missing}},
		"foreign environment": {"contexts": []map[string]string{{"environment_id": foreignEnv}}},
		"missing environment": {"contexts": []map[string]string{{"environment_id": missing}}},
		"foreign target":      {"contexts": []map[string]string{{"target_id": foreignTarget}}},
		"missing target":      {"contexts": []map[string]string{{"target_id": missing}}},
		"foreign artifact":    {"contexts": []map[string]string{{"artifact_id": foreignArtifact}}},
		"missing artifact":    {"contexts": []map[string]string{{"artifact_id": missing}}},
	}
	for name, body := range bodies {
		t.Run("create "+name, func(t *testing.T) {
			body := mergeAnyMap(map[string]any{"name": name}, body)
			status, raw := doJSON(t, http.MethodPost, base, adminToken, body)
			require.Equalf(t, http.StatusNotFound, status, "%s", raw)
		})
		t.Run("update "+name, func(t *testing.T) {
			status, raw := doJSON(t, http.MethodPut, base+"/"+own.ID, adminToken, body)
			require.Equalf(t, http.StatusNotFound, status, "%s", raw)
		})
	}

	// A foreign id and a missing id are indistinguishable.
	_, foreignBody := doJSON(t, http.MethodPost, base, adminToken, map[string]any{"name": "f", "target_ids": []string{foreignFinding}})
	_, missingBody := doJSON(t, http.MethodPost, base, adminToken, map[string]any{"name": "m", "target_ids": []string{missing}})
	require.JSONEq(t, string(foreignBody), string(missingBody))

	t.Run("malformed ids", func(t *testing.T) {
		for name, body := range map[string]map[string]any{
			"finding":     {"name": "x", "target_ids": []string{"nope"}},
			"environment": {"name": "x", "contexts": []map[string]string{{"environment_id": "nope"}}},
		} {
			status, raw := doJSON(t, http.MethodPost, base, adminToken, body)
			require.Equalf(t, http.StatusBadRequest, status, "%s: %s", name, raw)
		}
	})

	after := request[[]waiverScopeDetail](t, http.MethodGet, base, adminToken, nil, http.StatusOK)
	require.Len(t, after, len(before), "no refused call stored a waiver")
	detail := request[waiverDetail](t, http.MethodGet, base+"/"+own.ID, adminToken, nil, http.StatusOK)
	require.Len(t, detail.Targets, 1)
	require.Equal(t, ownFinding.ID, detail.Targets[0].FindingID, "no refused update changed the scope")

	// The project's own ids still work.
	own2 := request[waiverScopeDetail](t, http.MethodPost, base, adminToken, map[string]any{
		"name": "own env", "target_ids": []string{ownFinding.ID},
	}, http.StatusCreated)
	require.NotEmpty(t, own2.ID)
}

func mergeAnyMap(dst, src map[string]any) map[string]any {
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

// TestE2E_ReportScopedChecksAnswerAlikeForMissingAndForeignReports: the
// pull-request check and the introduced-only gate answer 403
// project_access_denied for a report id that does not exist and for one that
// belongs to another project, and 400 invalid_id for a malformed id.
func TestE2E_ReportScopedChecksAnswerAlikeForMissingAndForeignReports(t *testing.T) {
	slug := newProject(t, "report-scope")
	other := newProject(t, "report-scope-other")
	const sha = "dddddddddddddddddddddddddddddddddddddddd"
	own := request[ingestResponse](t, http.MethodPost, "/api/v1/reports", mintKey(t, slug),
		ingestBodyWith(t, slug, "high.sarif.json", map[string]any{"commit_sha": sha}), http.StatusCreated)
	foreign := request[ingestResponse](t, http.MethodPost, "/api/v1/reports", mintKey(t, other),
		ingestBodyWith(t, other, "high.sarif.json", map[string]any{"commit_sha": sha}), http.StatusCreated)
	const missing = "00000000-0000-4000-8000-00000000dead"

	prCheck := func(reportID string) (int, []byte) {
		return doJSON(t, http.MethodGet, "/api/v1/projects/"+slug+"/pr-check?provider=github&commit="+sha+"&report_id="+reportID, adminToken, nil)
	}
	gate := func(reportID string) (int, []byte) {
		return doJSON(t, http.MethodGet, "/api/v1/projects/"+slug+"/gate?introduced_only=1&report_id="+reportID, adminToken, nil)
	}
	for name, call := range map[string]func(string) (int, []byte){"pr-check": prCheck, "gate": gate} {
		t.Run(name, func(t *testing.T) {
			foreignStatus, foreignBody := call(foreign.ReportID)
			missingStatus, missingBody := call(missing)
			require.Equal(t, http.StatusForbidden, foreignStatus, "%s", foreignBody)
			require.Equal(t, http.StatusForbidden, missingStatus, "%s", missingBody)
			require.JSONEq(t, string(foreignBody), string(missingBody), "the answers are indistinguishable")
			require.Contains(t, string(missingBody), "project_access_denied")

			status, body := call("not-a-uuid")
			require.Equalf(t, http.StatusBadRequest, status, "%s", body)
			require.Contains(t, string(body), "invalid_id")

			status, body = call(own.ReportID)
			require.Equalf(t, http.StatusOK, status, "the project's own report still works: %s", body)
		})
	}
}
