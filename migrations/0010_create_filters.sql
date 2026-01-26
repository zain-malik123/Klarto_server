-- Migration 0010: create filters table
BEGIN;

CREATE TABLE IF NOT EXISTS filters (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL,
  name text NOT NULL,
  query text NOT NULL,
  color text NOT NULL,
  is_favorite boolean NOT NULL DEFAULT false,
  description text,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT fk_filters_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_filters_user_id ON filters(user_id);

COMMIT;
