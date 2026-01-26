-- Migration: add profile picture column to users and activities table
BEGIN;

-- Add profile_picture_base64 to users if it doesn't exist
ALTER TABLE public.users
  ADD COLUMN IF NOT EXISTS profile_picture_base64 text;

-- Create activities table (used by server logging)
CREATE TABLE IF NOT EXISTS public.activities (
  id uuid DEFAULT public.uuid_generate_v4() PRIMARY KEY,
  user_id uuid NOT NULL,
  activity_name character varying(255) NOT NULL,
  description text,
  created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_activities_user ON public.activities (user_id);

COMMIT;
