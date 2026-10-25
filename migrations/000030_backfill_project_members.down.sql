-- The backfill cannot be undone exactly: the up migration recorded nothing,
-- and a viewer row it inserted looks the same as one an admin added before or
-- after it. Deleting every viewer row (what this file used to do) also removed
-- every ordinary membership once 000036's down had renamed member to viewer.
-- The rows are kept instead. They grant each user read access the backfill
-- already gave, and re-applying the up migration skips them through
-- ON CONFLICT.
SELECT 1;
