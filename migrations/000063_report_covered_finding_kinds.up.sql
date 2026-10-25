-- The finding kinds a report examined, as the parser declared them. Auto-fix
-- retires a scope row only for these kinds, and a report delete needs the
-- same answer later to tell whether a newer clean report already retired the
-- evidence that remains. NULL is a report stored before this column: it
-- vouches for no kind, so it never counts as having retired anything.
ALTER TABLE reports ADD COLUMN covered_finding_kinds TEXT[];
