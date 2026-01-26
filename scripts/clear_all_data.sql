-- WARNING: This script WILL DELETE ALL DATA in the public schema.
-- It truncates every table in `public` except common migration tables
-- (keeps schema objects) and restarts sequences.
-- TAKE A DATABASE BACKUP BEFORE RUNNING.
-- Usage (Windows PowerShell):
-- psql -h <host> -p <port> -U <user> -d <database> -f scripts/clear_all_data.sql

BEGIN;

-- Dynamically truncate all tables in public schema except migration tables
DO
$$
DECLARE
  r RECORD;
BEGIN
  FOR r IN (
    SELECT tablename
    FROM pg_tables
    WHERE schemaname = 'public'
      AND tablename NOT IN ('schema_migrations', 'migrations')
  ) LOOP
    EXECUTE format('TRUNCATE TABLE public.%I RESTART IDENTITY CASCADE;', r.tablename);
  END LOOP;
END
$$;

COMMIT;

-- Execute VACUUM FULL on public tables (outside of functions).
-- This uses psql's `\gexec` to run generated VACUUM statements.
-- Note: `\gexec` is a psql client-side meta-command; run this script with psql.
SELECT 'VACUUM FULL ' || quote_ident(schemaname) || '.' || quote_ident(tablename) || ';'
FROM pg_tables
WHERE schemaname = 'public'
  AND tablename NOT IN ('schema_migrations', 'migrations');

\gexec

-- Note:
-- - This truncates tables and cascades to dependent tables, resetting serial/identity sequences.
-- - If you want to preserve certain tables (e.g. 'users'), add them to the NOT IN(...) list above.
-- - Always backup before running.
