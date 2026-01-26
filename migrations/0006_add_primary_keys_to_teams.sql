-- Migration 0006: ensure primary keys on teams and team_members
BEGIN;

-- Add primary key to teams.id if not present
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint c
        JOIN pg_class t ON c.conrelid = t.oid
        WHERE t.relname = 'teams' AND c.contype = 'p'
    ) THEN
        ALTER TABLE public.teams ADD CONSTRAINT teams_pkey PRIMARY KEY (id);
    END IF;
END$$;

-- Add primary key to team_members.id if not present
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint c
        JOIN pg_class t ON c.conrelid = t.oid
        WHERE t.relname = 'team_members' AND c.contype = 'p'
    ) THEN
        ALTER TABLE public.team_members ADD CONSTRAINT team_members_pkey PRIMARY KEY (id);
    END IF;
END$$;

COMMIT;
