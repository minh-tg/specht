ALTER TABLE projects DROP COLUMN IF EXISTS policy_template_id;

DROP TABLE IF EXISTS policy_templates;
