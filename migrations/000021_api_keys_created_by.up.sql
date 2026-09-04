ALTER TABLE api_keys
    ADD COLUMN created_by UUID REFERENCES users(id);

INSERT INTO users (email, display_name, password_hash, role)
VALUES ('system@specht.local', 'Specht system', NULL, 'member')
ON CONFLICT DO NOTHING;

UPDATE api_keys AS k
SET created_by = COALESCE(
    (SELECT pm.user_id
     FROM project_members pm
     WHERE pm.project_id = k.project_id
       AND pm.role = 'admin'
     ORDER BY pm.created_at, pm.user_id
     LIMIT 1),
    (SELECT pm.user_id
     FROM project_members pm
     WHERE pm.project_id = k.project_id
     ORDER BY pm.created_at, pm.user_id
     LIMIT 1),
    (SELECT u.id
     FROM users u
     WHERE u.email = 'system@specht.local'
     LIMIT 1),
    (SELECT u.id
     FROM users u
     ORDER BY u.created_at, u.id
     LIMIT 1)
)
WHERE k.created_by IS NULL;
