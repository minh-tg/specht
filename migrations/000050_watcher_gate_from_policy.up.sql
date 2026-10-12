-- The watcher gate now comes from the effective policy (key watcher_gate)
-- alone. Until now the gate read projects.cve_watcher_gate while the policy
-- screen showed policy.watcher_gate, whose built-in default differed, so the
-- two could disagree. The column is kept for one release and no longer read.
--
-- Keep every project's current gate: wherever the policy would resolve to
-- something other than the column's value, write the column's value as a
-- project override. A project that already resolves to it is left alone, and
-- one that carries an override gets it set to what the gate has been doing.
-- The policy resolves override, then template, then the built-in default
-- (require_triage).
UPDATE projects p
SET settings = jsonb_set(
        COALESCE(p.settings, '{}'::jsonb),
        '{policy}',
        COALESCE(p.settings->'policy', '{}'::jsonb)
            || jsonb_build_object('watcher_gate', p.cve_watcher_gate),
        true)
WHERE jsonb_exists(COALESCE(p.settings->'policy', '{}'::jsonb), 'watcher_gate')
   OR COALESCE(
          (SELECT lower(t.definition->>'watcher_gate')
             FROM policy_templates t
            WHERE t.id = p.policy_template_id),
          'require_triage'
      ) <> p.cve_watcher_gate;
