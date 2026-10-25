DROP FUNCTION IF EXISTS report_examined_finding(TEXT, TEXT[], TEXT[], UUID, TEXT, TEXT);
ALTER TABLE reports DROP COLUMN IF EXISTS examined_keys;
