DROP TRIGGER IF EXISTS waiver_deletions_no_truncate ON waiver_deletions;
DROP FUNCTION IF EXISTS waiver_deletions_refuse_truncate();
DROP TRIGGER IF EXISTS waiver_deletions_no_delete ON waiver_deletions;
DROP FUNCTION IF EXISTS waiver_deletions_refuse_delete();
