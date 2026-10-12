//go:build integration

package repo

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/golang-migrate/migrate/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/policy"
)

// TestWatcherGateMigration_KeepsEveryProjectsEffectiveGate compares, for every
// combination of the old column, a template and a project override, the gate
// a project had before the migration (the column) with what the effective
// policy resolves to after it. Nothing may flip.
func TestWatcherGateMigration_KeepsEveryProjectsEffectiveGate(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	m, err := migrate.New("file://../../migrations", repos.pool.Config().ConnString())
	require.NoError(t, err)
	defer func() { _, _ = m.Close() }()
	require.NoError(t, m.Migrate(49), "step back to before the watcher gate migration")

	modes := []string{"require_triage", "immediate", "off"}
	templates := []string{"none", "unset", "require_triage", "immediate", "off"}
	overrides := []string{"none", "require_triage", "immediate", "off"}

	templateIDs := map[string]string{}
	for _, tpl := range templates {
		if tpl == "none" {
			continue
		}
		definition := `{}`
		if tpl != "unset" {
			definition = fmt.Sprintf(`{"watcher_gate":%q}`, tpl)
		}
		var id string
		require.NoError(t, repos.pool.QueryRow(ctx,
			`INSERT INTO policy_templates (name, definition) VALUES ($1, $2::jsonb) RETURNING id::text`,
			"tpl-"+tpl, definition).Scan(&id))
		templateIDs[tpl] = id
	}

	type combo struct{ column, template, override string }
	var combos []combo
	for _, column := range modes {
		for _, tpl := range templates {
			for _, override := range overrides {
				combos = append(combos, combo{column, tpl, override})
			}
		}
	}
	slugs := map[string]combo{}
	for i, c := range combos {
		slug := fmt.Sprintf("p%03d", i)
		settings := `{}`
		if c.override != "none" {
			settings = fmt.Sprintf(`{"policy":{"watcher_gate":%q}}`, c.override)
		}
		var templateID any
		if id, ok := templateIDs[c.template]; ok {
			templateID = id
		}
		_, err := repos.pool.Exec(ctx,
			`INSERT INTO projects (slug, name, settings, policy_template_id, cve_watcher_gate)
			 VALUES ($1, $1, $2::jsonb, $3::uuid, $4)`,
			slug, settings, templateID, c.column)
		require.NoError(t, err)
		slugs[slug] = c
	}

	require.NoError(t, m.Up())

	changed := 0
	for slug, c := range slugs {
		var rawSettings []byte
		var templateDef []byte
		require.NoError(t, repos.pool.QueryRow(ctx,
			`SELECT p.settings, COALESCE(t.definition, '{}'::jsonb)
			   FROM projects p LEFT JOIN policy_templates t ON t.id = p.policy_template_id
			  WHERE p.slug = $1`, slug).Scan(&rawSettings, &templateDef))

		var doc struct {
			Policy json.RawMessage `json:"policy"`
		}
		require.NoError(t, json.Unmarshal(rawSettings, &doc))
		overrideDef, err := policy.ParseDefinition(doc.Policy)
		require.NoError(t, err, slug)
		templateParsed, err := policy.ParseDefinition(templateDef)
		require.NoError(t, err, slug)
		var name *string
		if c.template != "none" {
			n := "tpl-" + c.template
			name = &n
		}

		after := policy.Resolve(name, 1, templateParsed, overrideDef).WatcherGate

		assert.Equal(t, c.column, after,
			"column=%s template=%s override=%s: the gate must not change", c.column, c.template, c.override)

		if _, wrote := overrideDef["watcher_gate"]; wrote && c.override == "none" {
			changed++
		}
	}
	assert.Positive(t, changed, "some projects needed an override written")

	// A project that already resolves to its column value and carries no
	// override is left exactly as it was.
	var settings string
	require.NoError(t, repos.pool.QueryRow(ctx,
		`SELECT settings::text FROM projects WHERE cve_watcher_gate = 'require_triage' AND policy_template_id IS NULL AND settings = '{}'::jsonb LIMIT 1`).Scan(&settings))
	assert.Equal(t, "{}", settings)

	require.NoError(t, m.Migrate(49), "down is a no-op")
	require.NoError(t, m.Up(), "up, down, up must be repeatable")
}
