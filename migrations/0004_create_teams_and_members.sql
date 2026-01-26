-- Migration: create teams and team_members tables if missing
BEGIN;

CREATE TABLE IF NOT EXISTS public.teams (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    owner_id uuid NOT NULL,
    name character varying(255) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE IF EXISTS public.teams OWNER TO klarto_api_user;

CREATE TABLE IF NOT EXISTS public.team_members (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    team_id uuid NOT NULL,
    user_id uuid NOT NULL,
    role character varying(50) DEFAULT 'member' NOT NULL,
    joined_at timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE IF EXISTS public.team_members OWNER TO klarto_api_user;

CREATE INDEX IF NOT EXISTS idx_team_members_team ON public.team_members (team_id);
CREATE INDEX IF NOT EXISTS idx_team_members_user ON public.team_members (user_id);

COMMIT;
