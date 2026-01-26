-- Migration: create invitations table (if missing)
BEGIN;

CREATE TABLE IF NOT EXISTS public.invitations (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    team_id uuid NOT NULL,
    inviter_id uuid NOT NULL,
    invited_user_id uuid,
    email character varying(255) NOT NULL,
    invite_token character varying(255) NOT NULL,
    invite_token_expires_at timestamp with time zone,
    status character varying(50) DEFAULT 'pending',
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    accepted_at timestamp with time zone
);

ALTER TABLE IF EXISTS public.invitations OWNER TO klarto_api_user;

CREATE INDEX IF NOT EXISTS idx_invitations_token ON public.invitations USING btree (invite_token);

COMMIT;
