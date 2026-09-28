//go:build e2e

package e2e

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// prCommit is the revision the baseline findings are attributed to, so the
// PR preview scopes to exactly that change.
const prCommit = "abcd0000abcd0000abcd0000abcd0000abcd0000"

// unknownCommit names a revision no report ever introduced.
const unknownCommit = "0000dead0000dead0000dead0000dead0000dead"

// Local response shapes for the planning previews.

type prCheckAnnotation struct {
	FindingID string `json:"finding_id"`
	File      string `json:"file"`
	StartLine int    `json:"start_line"`
	Title     string `json:"title"`
}

type prCheckPreview struct {
	Provider    string              `json:"provider"`
	CommitSha   string              `json:"commit_sha"`
	Conclusion  string              `json:"conclusion"`
	Title       string              `json:"title"`
	Summary     string              `json:"summary"`
	Annotations []prCheckAnnotation `json:"annotations"`
	WaivedCount int                 `json:"waived_count"`
}

type notifyPlan struct {
	ID        string `json:"id"`
	Channel   string `json:"channel"`
	Target    string `json:"target"`
	Action    string `json:"action"`
	Title     string `json:"title"`
	Body      string `json:"body"`
	DedupeKey string `json:"dedupe_key"`
}

type notifyOutcome struct {
	Supported bool        `json:"supported"`
	Plan      *notifyPlan `json:"plan"`
	Reason    string      `json:"reason"`
}

type patchOutcome struct {
	Supported bool   `json:"supported"`
	Reason    string `json:"reason"`
}

// TestE2E_PreviewsPlanWithoutSideEffects covers the three planning
// surfaces: the PR-check preview scoped to a change, the notification
// plan/refusal contract, and the safe-patch refusal contract — each with
// its validation and denial edges, driven through the API and the CLI
// exactly as a CI pipeline would consume them. Previews plan; they never
// publish or mutate.
func TestE2E_PreviewsPlanWithoutSideEffects(t *testing.T) {
	slug := newProject(t, "previews")
	key := mintKey(t, slug)
	viewerToken := login(t, "e2e-viewer@example.com", adminPass)
	viewerMe := request[userProfile](t, http.MethodGet, "/api/v1/me", viewerToken, nil, http.StatusOK)
	request[memberResponse](t, http.MethodPost, "/api/v1/projects/"+slug+"/members", adminToken,
		map[string]string{"user_id": viewerMe.ID, "role": "viewer"}, http.StatusCreated)

	request[ingestResponse](t, http.MethodPost, "/api/v1/reports", key,
		ingestBodyWith(t, slug, "high-medium.sarif.json", map[string]any{
			"commit_sha": prCommit,
		}), http.StatusCreated)
	high := highFinding(t, slug)

	t.Run("pr check plans a failing change and flips with the gate", func(t *testing.T) {
		status, raw := doJSON(t, http.MethodGet,
			"/api/v1/projects/"+slug+"/pr-check", adminToken, nil)
		require.Equal(t, http.StatusBadRequest, status)
		require.Equal(t, "missing_commit", errorCode(t, raw))

		status, raw = doJSON(t, http.MethodGet,
			"/api/v1/projects/"+slug+"/pr-check?commit="+prCommit+"&provider=carrier-pigeon",
			adminToken, nil)
		require.Equal(t, http.StatusBadRequest, status)
		require.Equal(t, "unknown_provider", errorCode(t, raw))

		plan := request[prCheckPreview](t, http.MethodGet,
			"/api/v1/projects/"+slug+"/pr-check?commit="+prCommit, adminToken, nil, http.StatusOK)
		require.Equal(t, "github", plan.Provider)
		require.Equal(t, prCommit, plan.CommitSha)
		require.Equal(t, "failure", plan.Conclusion,
			"an unwaived blocking finding introduced by the commit fails the check")
		require.NotEmpty(t, plan.Title)
		require.NotEmpty(t, plan.Summary)
		require.Zero(t, plan.WaivedCount)
		var annotation *prCheckAnnotation
		for i := range plan.Annotations {
			if plan.Annotations[i].FindingID == high.ID {
				annotation = &plan.Annotations[i]
			}
		}
		require.NotNil(t, annotation, "the blocking high maps to an inline annotation")
		require.Equal(t, "src/config.go", annotation.File)
		require.Equal(t, 12, annotation.StartLine)

		empty := request[prCheckPreview](t, http.MethodGet,
			"/api/v1/projects/"+slug+"/pr-check?commit="+unknownCommit, adminToken, nil, http.StatusOK)
		require.Equal(t, "success", empty.Conclusion,
			"a commit that introduced nothing passes")
		require.Empty(t, empty.Annotations)

		request[prCheckPreview](t, http.MethodGet,
			"/api/v1/projects/"+slug+"/pr-check?commit="+prCommit, viewerToken, nil, http.StatusOK)

		keyPlan := request[prCheckPreview](t, http.MethodGet,
			"/api/v1/projects/"+slug+"/pr-check?commit="+prCommit, key, nil, http.StatusOK)
		require.Equal(t, "failure", keyPlan.Conclusion,
			"a project key with read scope may plan the check")

		stdout, stderr, exit := runBin(t, cliBin,
			[]string{"API_URL=" + baseURL, "API_KEY=" + key},
			"pr", "preview", "--project", slug, "--commit", prCommit)
		require.Equal(t, 0, exit, "a preview plans; it never fails the build; stderr:\n%s", stderr)
		require.Contains(t, stdout, "check failure")
		require.Contains(t, stdout, "src/config.go:12")

		_, _, exit = runBin(t, cliBin,
			[]string{"API_URL=" + baseURL, "API_KEY=" + key},
			"pr", "preview", "--project", slug)
		require.Equal(t, 2, exit, "commit is a required flag")

		request[triageOutput](t, http.MethodPatch, "/api/v1/findings/"+high.ID, adminToken,
			map[string]any{
				"analysis_state": "false_positive",
				"reason":         "fixture finding, not a real vulnerability",
			}, http.StatusOK)

		flipped := request[prCheckPreview](t, http.MethodGet,
			"/api/v1/projects/"+slug+"/pr-check?commit="+prCommit, adminToken, nil, http.StatusOK)
		require.Equal(t, "success", flipped.Conclusion,
			"the plan tracks the live gate: triaging the blocker passes the check")
		require.Empty(t, flipped.Annotations,
			"no unwaived blocking finding remains to annotate")
	})

	t.Run("notify preview plans or refuses explicitly", func(t *testing.T) {
		status, raw := doJSON(t, http.MethodGet,
			"/api/v1/findings/"+high.ID+"/notify-preview?target=github.com/acme/widgets",
			adminToken, nil)
		require.Equal(t, http.StatusBadRequest, status)
		require.Equal(t, "missing_channel", errorCode(t, raw))

		status, raw = doJSON(t, http.MethodGet,
			"/api/v1/findings/"+high.ID+"/notify-preview?channel=issue", adminToken, nil)
		require.Equal(t, http.StatusBadRequest, status)
		require.Equal(t, "missing_target", errorCode(t, raw))

		refused := request[notifyOutcome](t, http.MethodGet,
			"/api/v1/findings/"+high.ID+"/notify-preview?channel=carrier-pigeon&target=x",
			adminToken, nil, http.StatusOK)
		require.False(t, refused.Supported, "a refusal is an outcome, not an error")
		require.Contains(t, refused.Reason, "unsupported channel")
		require.Nil(t, refused.Plan, "a refusal never carries a partial plan")

		plan := request[notifyOutcome](t, http.MethodGet,
			"/api/v1/findings/"+high.ID+"/notify-preview?channel=issue&target=github.com/acme/widgets",
			adminToken, nil, http.StatusOK)
		require.True(t, plan.Supported)
		require.NotNil(t, plan.Plan)
		require.Equal(t, "issue", plan.Plan.Channel)
		require.Equal(t, "github.com/acme/widgets", plan.Plan.Target)
		require.Equal(t, "create", plan.Plan.Action,
			"an unlinked finding plans an item creation")
		require.Equal(t, "[HIGH] "+high.CurrentTitle, plan.Plan.Title)
		require.NotEmpty(t, plan.Plan.Body)
		require.Equal(t, plan.Plan.DedupeKey, plan.Plan.ID,
			"plan and dedupe identity come from the same evidence")
		require.Contains(t, plan.Plan.DedupeKey, "notify-")

		linked := request[notifyOutcome](t, http.MethodGet,
			"/api/v1/findings/"+high.ID+"/notify-preview?channel=issue&target=github.com/acme/widgets&linked=true",
			adminToken, nil, http.StatusOK)
		require.True(t, linked.Supported)
		require.Equal(t, "update", linked.Plan.Action,
			"an already-linked finding plans a refresh, not a duplicate")

		status, raw = doJSON(t, http.MethodGet,
			"/api/v1/findings/not-a-uuid/notify-preview?channel=issue&target=t", adminToken, nil)
		require.Equal(t, http.StatusBadRequest, status)
		require.Equal(t, "invalid_id", errorCode(t, raw))

		unknown := randomHex(16)
		status, raw = doJSON(t, http.MethodGet,
			"/api/v1/findings/"+unknown+"/notify-preview?channel=issue&target=t", adminToken, nil)
		require.Equal(t, http.StatusNotFound, status)
		require.Equal(t, "not_found", errorCode(t, raw))

		request[notifyOutcome](t, http.MethodGet,
			"/api/v1/findings/"+high.ID+"/notify-preview?channel=issue&target=github.com/acme/widgets",
			viewerToken, nil, http.StatusOK)

		stdout, stderr, exit := runBin(t, cliBin,
			[]string{"API_URL=" + baseURL, "API_KEY=" + key},
			"notify", "preview", "--finding", high.ID,
			"--channel", "issue", "--target", "github.com/acme/widgets")
		require.Equal(t, 0, exit, "stderr:\n%s", stderr)
		require.Contains(t, stdout, "notify ")
		require.Contains(t, stdout, "dedupe: notify-")

		stdout, stderr, exit = runBin(t, cliBin,
			[]string{"API_URL=" + baseURL, "API_KEY=" + key},
			"notify", "preview", "--finding", high.ID,
			"--channel", "carrier-pigeon", "--target", "x")
		require.Equal(t, 0, exit, "a refusal prints; it never errors; stderr:\n%s", stderr)
		require.Contains(t, stdout, "no notification: unsupported channel")

		_, stderr, exit = runBin(t, cliBin,
			[]string{"API_URL=" + baseURL, "API_KEY=" + key},
			"notify", "preview", "--finding", high.ID, "--target", "x")
		require.Equal(t, 2, exit, "channel is a required flag")
	})

	t.Run("patch preview refuses without partial patches", func(t *testing.T) {
		outcome := request[patchOutcome](t, http.MethodGet,
			"/api/v1/findings/"+high.ID+"/patch-preview", adminToken, nil, http.StatusOK)
		require.False(t, outcome.Supported,
			"a SAST finding without deterministic upgrade evidence is refused")
		require.NotEmpty(t, outcome.Reason, "every refusal carries its reason")

		status, raw := doJSON(t, http.MethodGet,
			"/api/v1/findings/not-a-uuid/patch-preview", adminToken, nil)
		require.Equal(t, http.StatusBadRequest, status)
		require.Equal(t, "invalid_id", errorCode(t, raw))

		unknown := randomHex(16)
		status, raw = doJSON(t, http.MethodGet,
			"/api/v1/findings/"+unknown+"/patch-preview", adminToken, nil)
		require.Equal(t, http.StatusNotFound, status)
		require.Equal(t, "not_found", errorCode(t, raw))

		request[patchOutcome](t, http.MethodGet,
			"/api/v1/findings/"+high.ID+"/patch-preview", key, nil, http.StatusOK)

		stdout, stderr, exit := runBin(t, cliBin,
			[]string{"API_URL=" + baseURL, "API_KEY=" + key},
			"patch", "preview", "--finding", high.ID)
		require.Equal(t, 0, exit, "a refusal prints; it never errors; stderr:\n%s", stderr)
		require.Contains(t, stdout, "no patch: no deterministic transformation")

		_, stderr, exit = runBin(t, cliBin,
			[]string{"API_URL=" + baseURL, "API_KEY=" + key},
			"patch", "preview")
		require.Equal(t, 2, exit, "finding is a required flag")
	})
}
