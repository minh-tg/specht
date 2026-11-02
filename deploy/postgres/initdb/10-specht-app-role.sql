-- The role the Specht server runs its queries as, with the table access the
-- server needs and nothing more: SELECT, INSERT, UPDATE and DELETE on every
-- table and USAGE on every sequence in the public schema. It cannot create,
-- alter, truncate or drop anything, and the append-only triggers on its
-- tables bind it. Migrations keep running as the owner (MIGRATE_DATABASE_URL).
--
-- The postgres image runs this file once, when it creates the database, as
-- POSTGRES_USER, which becomes the owner of every table the migrations make.
-- It is safe to run again, and an existing install runs it by hand once (see
-- deploy/README.md, "Database roles"):
--
--   psql -v ON_ERROR_STOP=1 -U specht -d specht -f 10-specht-app-role.sql
--
-- Settings come from the environment:
--   SPECHT_APP_DB_PASSWORD  the role's password (required)
--   SPECHT_APP_DB_USER      the role's name (default specht_app)
-- and from psql variables:
--   owner_role              the role that runs the migrations (default: the
--                           user running this file), whose future tables the
--                           app role is granted automatically
--
-- Functions the migrations create keep PostgreSQL's default EXECUTE for
-- PUBLIC, so the role needs no grant for them.

\set ON_ERROR_STOP on

\if :{?app_role}
\else
\set app_role specht_app
\getenv app_role SPECHT_APP_DB_USER
\endif
\set app_password ''
\getenv app_password SPECHT_APP_DB_PASSWORD
\if :{?owner_role}
\else
\set owner_role :USER
\endif

SELECT 'DO $$ BEGIN RAISE EXCEPTION ''SPECHT_APP_DB_PASSWORD is not set''; END $$'
WHERE :'app_password' = '' \gexec
SELECT 'DO $$ BEGIN RAISE EXCEPTION ''SPECHT_APP_DB_USER is empty''; END $$'
WHERE :'app_role' = '' \gexec
SELECT 'DO $$ BEGIN RAISE EXCEPTION ''the app role must differ from the owner role''; END $$'
WHERE :'app_role' = :'owner_role' \gexec

SELECT format('CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS', :'app_role')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'app_role') \gexec
SELECT format('ALTER ROLE %I WITH LOGIN PASSWORD %L', :'app_role', :'app_password') \gexec

-- Changing these attributes on an existing role needs a superuser, so a role
-- that has one is refused instead of quietly kept.
SELECT format(
    'DO $$ BEGIN RAISE EXCEPTION %L; END $$',
    format('role %s has SUPERUSER, CREATEDB, CREATEROLE, REPLICATION or BYPASSRLS; '
        'run ALTER ROLE %s NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS first',
        quote_ident(rolname), quote_ident(rolname)))
FROM pg_roles
WHERE rolname = :'app_role'
  AND (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls) \gexec

SELECT format('GRANT CONNECT ON DATABASE %I TO %I', current_database(), :'app_role') \gexec
SELECT format('GRANT USAGE ON SCHEMA public TO %I', :'app_role') \gexec
SELECT format('GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO %I', :'app_role') \gexec
SELECT format('GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO %I', :'app_role') \gexec
SELECT format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO %I',
    :'owner_role', :'app_role') \gexec
SELECT format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO %I',
    :'owner_role', :'app_role') \gexec
