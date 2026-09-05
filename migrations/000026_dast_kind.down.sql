-- Remove the DAST kind. Fails if dast findings exist (delete them first).
DELETE FROM finding_kinds WHERE code = 'dast';
