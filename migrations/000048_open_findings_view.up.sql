-- One definition of an open finding, shared by the statistics, the gate's
-- candidate loader and the aging report. A finding that is fixed (or, later,
-- archived) is not open, so it neither counts nor blocks nor ages.
--
-- The view lists the findings columns as they are today. A column added to
-- findings later has to be added here before a query can select it through the
-- view.
CREATE VIEW open_findings AS
SELECT *
FROM findings
WHERE state IN ('open', 'reopened');
