# Migration safety policy

Migrations are applied automatically in deployments, so an applied migration must
be safe to run once and safe to recover from when a release needs to be reverted.
Never edit an applied migration; add a new migration instead.

## Destructive changes

A migration that drops a table or column, narrows a type, or otherwise discards
information **must preserve the data before the destructive statement**. Use one
of these approaches:

- copy the affected rows into a clearly named, temporary backup table (with a
  retention/cleanup plan); or
- export the affected rows and retain the export with the deployment backup.

The migration description must identify the backup and its retention period.
The corresponding `down.sql` must restore the schema and should restore the
preserved values whenever the backup is available. A rollback cannot recover
values that were discarded without a backup, so a down migration that only
recreates empty columns is not considered data-safe.

For example, before removing an obsolete column:

```sql
CREATE TABLE migration_000035_old_widget_values AS
SELECT id, old_widget FROM widgets;

ALTER TABLE widgets DROP COLUMN old_widget;
```

The backup table is retained until the release's rollback window expires, then
removed by a separately reviewed cleanup migration. For large tables, use an
export or an online, staged migration rather than holding a long table lock.

Every migration must have an up and down file. CI applies the complete chain,
rolls it back one migration at a time, and applies it again on a clean
PostgreSQL database.
