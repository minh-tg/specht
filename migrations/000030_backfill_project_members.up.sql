-- Backfill project membership for the tenant-isolation enforcement.
-- Every pre-existing user keeps access to every pre-existing project as a
-- viewer (the least privilege preserving current read behavior; mutations
-- were never role-gated for session users). Users created after this
-- migration hold no memberships until an admin adds them; project creators
-- become admins automatically at creation time.
INSERT INTO project_members (project_id, user_id, role)
SELECT p.id, u.id, 'viewer'
FROM projects p CROSS JOIN users u
ON CONFLICT (project_id, user_id) DO NOTHING;
