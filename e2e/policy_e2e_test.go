//go:build e2e

package e2e

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// Local response shapes for the policy endpoints.

type policyTemplate struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Definition  map[string]string `json:"definition"`
	Version     int32             `json:"version"`
}

type policyEffective struct {
	TemplateName    *string `json:"template_name"`
	TemplateVersion int     `json:"template_version"`
	SeverityFloor   string  `json:"severity_floor"`
	SeveritySource  string  `json:"severity_source"`
	WatcherGate     string  `json:"watcher_gate"`
	WatcherSource   string  `json:"watcher_source"`
}

// TestE2E_PolicyTemplatesAndOverrides walks the policy business processes:
// template lifecycle with its definition grammar, linking a template to a
// project, per-key overrides with provenance precedence, and — the point of
// the whole feature — the gate actually honoring the effective floor, in
// both directions, with provenance exposed on the gate response itself.
func TestE2E_PolicyTemplatesAndOverrides(t *testing.T) {
	slug := newProject(t, "policy")
	key := mintKey(t, slug)
	ingestFixture(t, slug, key, "high-medium.sarif.json")
	viewerToken := login(t, "e2e-viewer@example.com", adminPass)

	templateName := "e2e-template-" + randomHex(4)

	t.Run("template lifecycle enforces the definition grammar", func(t *testing.T) {
		status, raw := doJSON(t, http.MethodPost, "/api/v1/policy-templates", viewerToken,
			map[string]any{"name": "viewer-template"})
		require.Equal(t, http.StatusForbidden, status)
		require.Equal(t, "insufficient_role", errorCode(t, raw),
			"template management is admin-session only")

		created := request[policyTemplate](t, http.MethodPost, "/api/v1/policy-templates", adminToken,
			map[string]any{
				"name": templateName, "description": "e2e baseline",
				"definition": map[string]string{"severity_floor": "critical"},
			}, http.StatusCreated)
		require.Equal(t, templateName, created.Name)
		require.Equal(t, "critical", created.Definition["severity_floor"])
		require.EqualValues(t, 1, created.Version)

		status, raw = doJSON(t, http.MethodPost, "/api/v1/policy-templates", adminToken,
			map[string]any{
				"name":       templateName,
				"definition": map[string]string{"severity_floor": "critical"},
			})
		require.Equal(t, http.StatusConflict, status)
		require.Equal(t, "policy_conflict", errorCode(t, raw))

		status, raw = doJSON(t, http.MethodPost, "/api/v1/policy-templates", adminToken,
			map[string]any{
				"name":       "bad-value-" + randomHex(4),
				"definition": map[string]string{"severity_floor": "urgent"},
			})
		require.Equal(t, http.StatusBadRequest, status)
		require.Equal(t, "invalid_policy", errorCode(t, raw),
			"unknown values are rejected, never silently dropped")

		status, raw = doJSON(t, http.MethodPost, "/api/v1/policy-templates", adminToken,
			map[string]any{
				"name":       "bad-key-" + randomHex(4),
				"definition": map[string]string{"shoesize": "9"},
			})
		require.Equal(t, http.StatusBadRequest, status)
		require.Equal(t, "invalid_policy", errorCode(t, raw))

		status, raw = doJSON(t, http.MethodPost, "/api/v1/policy-templates", adminToken,
			map[string]any{"name": "", "definition": map[string]string{}})
		require.Equal(t, http.StatusBadRequest, status)
		require.Equal(t, "invalid_policy", errorCode(t, raw))

		list := request[[]policyTemplate](t, http.MethodGet, "/api/v1/policy-templates", adminToken, nil, http.StatusOK)
		var found *policyTemplate
		for i := range list {
			if list[i].ID == created.ID {
				found = &list[i]
			}
		}
		require.NotNil(t, found, "the created template is listed")

		updated := request[policyTemplate](t, http.MethodPut,
			"/api/v1/policy-templates/"+created.ID, adminToken,
			map[string]any{
				"name": templateName, "description": "e2e baseline v2",
				"definition": map[string]string{
					"severity_floor": "critical",
					"watcher_gate":   "off",
				},
			}, http.StatusOK)
		require.Equal(t, "off", updated.Definition["watcher_gate"])
		require.Greater(t, updated.Version, created.Version,
			"redefining a baseline bumps its version so consumers can tell")

		unknown := randomHex(16)
		status, raw = doJSON(t, http.MethodPut, "/api/v1/policy-templates/"+unknown, adminToken,
			map[string]any{"name": "ghost", "definition": map[string]string{}})
		require.Equal(t, http.StatusNotFound, status)
		require.Equal(t, "not_found", errorCode(t, raw))

		status, raw = doJSON(t, http.MethodPut, "/api/v1/policy-templates/not-a-uuid", adminToken,
			map[string]any{"name": "ghost", "definition": map[string]string{}})
		require.Equal(t, http.StatusBadRequest, status)
		require.Equal(t, "invalid_id", errorCode(t, raw))
	})

	t.Run("the effective policy drives the gate with provenance", func(t *testing.T) {
		initial := request[policyEffective](t, http.MethodGet,
			"/api/v1/projects/"+slug+"/policy", adminToken, nil, http.StatusOK)
		require.Nil(t, initial.TemplateName)
		require.Equal(t, "high", initial.SeverityFloor)
		require.Equal(t, "default", initial.SeveritySource)
		require.Equal(t, "immediate", initial.WatcherGate)
		require.Equal(t, "default", initial.WatcherSource)

		status, raw := doJSON(t, http.MethodGet, "/api/v1/projects/"+slug+"/policy", viewerToken, nil)
		require.Equal(t, http.StatusForbidden, status)
		require.Equal(t, "project_access_denied", errorCode(t, raw),
			"policy reads are scoped to project members")

		request[policyEffective](t, http.MethodGet,
			"/api/v1/projects/"+slug+"/policy", key, nil, http.StatusOK)

		linked := request[policyEffective](t, http.MethodPut,
			"/api/v1/projects/"+slug+"/policy", adminToken,
			map[string]string{"template_name": templateName}, http.StatusOK)
		require.NotNil(t, linked.TemplateName)
		require.Equal(t, templateName, *linked.TemplateName)
		require.Equal(t, "critical", linked.SeverityFloor)
		require.Equal(t, "template", linked.SeveritySource)
		require.Equal(t, "off", linked.WatcherGate)
		require.Equal(t, "template", linked.WatcherSource)

		gs := getGate(t, slug, "")
		require.False(t, gs.ThresholdBreached,
			"a critical floor stops the baseline high from blocking")
		require.NotNil(t, gs.Policy, "the gate response carries its policy")
		require.Equal(t, "critical", gs.Policy.SeverityFloor)
		require.Equal(t, "template", gs.Policy.SeveritySource)
		require.NotNil(t, gs.Policy.TemplateName)
		require.Equal(t, templateName, *gs.Policy.TemplateName)

		overridden := request[policyEffective](t, http.MethodPut,
			"/api/v1/projects/"+slug+"/policy/overrides", adminToken,
			map[string]any{"overrides": map[string]string{"severity_floor": "high"}}, http.StatusOK)
		require.Equal(t, "high", overridden.SeverityFloor)
		require.Equal(t, "override", overridden.SeveritySource,
			"project overrides beat the template")

		gs = getGate(t, slug, "")
		require.True(t, gs.ThresholdBreached,
			"an override restoring the high floor re-blocks the baseline high")
		require.Equal(t, "override", gs.Policy.SeveritySource,
			"the gate explains which layer decided")

		status, raw = doJSON(t, http.MethodPut,
			"/api/v1/projects/"+slug+"/policy/overrides", adminToken,
			map[string]any{"overrides": map[string]string{"severity_floor": "urgent"}})
		require.Equal(t, http.StatusBadRequest, status)
		require.Equal(t, "invalid_policy", errorCode(t, raw))

		cleared := request[policyEffective](t, http.MethodPut,
			"/api/v1/projects/"+slug+"/policy/overrides", adminToken,
			map[string]any{"overrides": map[string]string{}}, http.StatusOK)
		require.Equal(t, "critical", cleared.SeverityFloor)
		require.Equal(t, "template", cleared.SeveritySource,
			"clearing overrides falls back to the template")

		unlinked := request[policyEffective](t, http.MethodPut,
			"/api/v1/projects/"+slug+"/policy", adminToken,
			map[string]string{"template_name": ""}, http.StatusOK)
		require.Nil(t, unlinked.TemplateName)
		require.Equal(t, "high", unlinked.SeverityFloor)
		require.Equal(t, "default", unlinked.SeveritySource)
		require.True(t, getGate(t, slug, "").ThresholdBreached,
			"unlinking the template restores the default floor and the block")

		status, raw = doJSON(t, http.MethodPut,
			"/api/v1/projects/"+slug+"/policy", adminToken,
			map[string]string{"template_name": "ghost-" + randomHex(4)})
		require.Equal(t, http.StatusNotFound, status)
		require.Equal(t, "not_found", errorCode(t, raw))

		status, raw = doJSON(t, http.MethodPut,
			"/api/v1/projects/"+slug+"/policy", viewerToken,
			map[string]string{"template_name": templateName})
		require.Equal(t, http.StatusForbidden, status)
		require.Equal(t, "project_access_denied", errorCode(t, raw),
			"non-members cannot reassign policy")

		status, raw = doJSON(t, http.MethodPut,
			"/api/v1/projects/"+slug+"/policy", key,
			map[string]string{"template_name": templateName})
		require.Equal(t, http.StatusForbidden, status)
		require.Equal(t, "insufficient_scope", errorCode(t, raw),
			"a project key without admin scope cannot reassign policy")
	})

	t.Run("template deletion is admin-only and reported honestly", func(t *testing.T) {
		templates := request[[]policyTemplate](t, http.MethodGet, "/api/v1/policy-templates", adminToken, nil, http.StatusOK)
		var id string
		for _, tpl := range templates {
			if tpl.Name == templateName {
				id = tpl.ID
			}
		}
		require.NotEmpty(t, id)

		status, raw := doJSON(t, http.MethodDelete, "/api/v1/policy-templates/"+id, viewerToken, nil)
		require.Equal(t, http.StatusForbidden, status)
		require.Equal(t, "insufficient_role", errorCode(t, raw))

		status, _ = doJSON(t, http.MethodDelete, "/api/v1/policy-templates/"+id, adminToken, nil)
		require.Equal(t, http.StatusNoContent, status)

		status, raw = doJSON(t, http.MethodDelete, "/api/v1/policy-templates/"+id, adminToken, nil)
		require.Equal(t, http.StatusNotFound, status)
		require.Equal(t, "not_found", errorCode(t, raw),
			"deleting a missing template reports 404")
	})
}
