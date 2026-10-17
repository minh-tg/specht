//go:build e2e

package e2e

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// sevScopeSarif builds a one-result SARIF document. Documents with the same
// rule and file name the same finding whatever their level says, so the level
// alone sets the severity of each scan.
func sevScopeSarif(level string) json.RawMessage {
	doc := map[string]any{
		"version": "2.1.0",
		"runs": []any{map[string]any{
			"tool": map[string]any{"driver": map[string]any{
				"name": "severity-scope", "version": "1.0.0",
				"rules": []any{map[string]any{"id": "SEV-SCOPE-1", "shortDescription": map[string]any{"text": "SQL injection"}}},
			}},
			"results": []any{map[string]any{
				"ruleId":  "SEV-SCOPE-1",
				"level":   level,
				"message": map[string]any{"text": "SQL injection"},
				"locations": []any{map[string]any{"physicalLocation": map[string]any{
					"artifactLocation": map[string]any{"uri": "src/app.go"},
					"region":           map[string]any{"startLine": 7},
				}}},
			}},
		}},
	}
	raw, _ := json.Marshal(doc)
	return raw
}

func sevScopeSHA(c byte) string { return strings.Repeat(string(c), 40) }

// sevScopeIngest posts one SARIF scan and fails the test unless it was accepted.
func sevScopeIngest(t *testing.T, key, slug string, raw json.RawMessage, extra map[string]any) {
	t.Helper()
	body := map[string]any{"project": slug, "scanner": "sarif", "raw_data": raw}
	for k, v := range extra {
		body[k] = v
	}
	status, out := doJSON(t, http.MethodPost, "/api/v1/reports", key, body)
	require.Containsf(t, []int{http.StatusCreated, http.StatusOK}, status, "ingest: %s", out)
}

type sevScopeFinding struct {
	ID              string `json:"id"`
	CurrentSeverity string `json:"current_severity"`
}

func sevScopeFindings(t *testing.T, slug string) []sevScopeFinding {
	t.Helper()
	return request[[]sevScopeFinding](t, http.MethodGet,
		"/api/v1/projects/"+slug+"/findings?limit=100&status=open,reopened,fixed", adminToken, nil, http.StatusOK)
}

// sevScopeEvent omits changes: the API returns that column base64-encoded, and
// the unit tests check its contents.
type sevScopeEvent struct {
	EventType string  `json:"event_type"`
	OldValue  *string `json:"old_value"`
	NewValue  *string `json:"new_value"`
}

// sevScopeChanges returns the severity_changed events of one finding.
func sevScopeChanges(t *testing.T, findingID string) []sevScopeEvent {
	t.Helper()
	events := request[[]sevScopeEvent](t, http.MethodGet, "/api/v1/findings/"+findingID+"/events", adminToken, nil, http.StatusOK)
	var out []sevScopeEvent
	for _, e := range events {
		if e.EventType == "severity_changed" {
			out = append(out, e)
		}
	}
	return out
}

// TestSeverityScope_R18_LowerBranchScanKeepsHighGate: a high reported on main
// stays high after a note-level scan from another branch. The gate still
// blocks on the high, and the feature scope's report is recorded as one event.
func TestSeverityScope_R18_LowerBranchScanKeepsHighGate(t *testing.T) {
	slug := newProject(t, "sev-scope-r18")
	key := mintKey(t, slug)

	sevScopeIngest(t, key, slug, sevScopeSarif("error"),
		map[string]any{"branch": "main", "commit_sha": sevScopeSHA('a')})
	require.True(t, getGate(t, slug, "").ThresholdBreached, "the main scan reports a high finding")

	sevScopeIngest(t, key, slug, sevScopeSarif("note"),
		map[string]any{"branch": "feature/unrelated", "commit_sha": sevScopeSHA('b')})

	fs := sevScopeFindings(t, slug)
	require.Len(t, fs, 1)
	require.Equal(t, "high", fs[0].CurrentSeverity, "the finding shows the highest severity across scopes")

	g := getGate(t, slug, "")
	require.True(t, g.ThresholdBreached, "the gate reads the project-wide severity, so the high still blocks")
	require.Equal(t, int64(1), g.BlockingCount)

	changed := sevScopeChanges(t, fs[0].ID)
	require.Len(t, changed, 1, "the feature scope's note-level report is recorded once")
	require.NotNil(t, changed[0].OldValue)
	require.NotNil(t, changed[0].NewValue)
	require.Equal(t, "high", *changed[0].OldValue)
	require.Equal(t, "low", *changed[0].NewValue)
}

// TestSeverityScope_RepeatInSameScopeWritesNoEvent: a second scan from the same
// branch at the same level changes nothing and writes no severity_changed event.
func TestSeverityScope_RepeatInSameScopeWritesNoEvent(t *testing.T) {
	slug := newProject(t, "sev-scope-repeat")
	key := mintKey(t, slug)

	sevScopeIngest(t, key, slug, sevScopeSarif("error"),
		map[string]any{"branch": "main", "commit_sha": sevScopeSHA('a')})
	sevScopeIngest(t, key, slug, sevScopeSarif("error"),
		map[string]any{"branch": "main", "commit_sha": sevScopeSHA('c')})

	fs := sevScopeFindings(t, slug)
	require.Len(t, fs, 1)
	require.Empty(t, sevScopeChanges(t, fs[0].ID))
}

// TestSeverityScope_SameScopeDowngradeWritesOneEvent: a downgrade inside the
// scope that made the finding high does lower the project-wide severity, and it
// writes exactly one event with the old and new values.
func TestSeverityScope_SameScopeDowngradeWritesOneEvent(t *testing.T) {
	slug := newProject(t, "sev-scope-downgrade")
	key := mintKey(t, slug)

	sevScopeIngest(t, key, slug, sevScopeSarif("error"),
		map[string]any{"branch": "main", "commit_sha": sevScopeSHA('a')})
	sevScopeIngest(t, key, slug, sevScopeSarif("note"),
		map[string]any{"branch": "main", "commit_sha": sevScopeSHA('b')})

	fs := sevScopeFindings(t, slug)
	require.Len(t, fs, 1)
	require.Equal(t, "low", fs[0].CurrentSeverity)
	require.False(t, getGate(t, slug, "").ThresholdBreached)

	changed := sevScopeChanges(t, fs[0].ID)
	require.Len(t, changed, 1)
	require.Equal(t, "high", *changed[0].OldValue)
	require.Equal(t, "low", *changed[0].NewValue)
}
