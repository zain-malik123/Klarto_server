-- Migration 0007: ensure labels table and todos.label_id + FK/index
BEGIN;

-- Create labels table if missing
CREATE TABLE IF NOT EXISTS labels (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL,
  color text,
  user_id uuid,
  team_id uuid,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- Add label_id column to todos if missing
ALTER TABLE IF EXISTS todos ADD COLUMN IF NOT EXISTS label_id uuid;

-- Add FK constraint to todos.label_id referencing labels(id) if not present
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint c
    JOIN pg_class t ON c.conrelid = t.oid
    WHERE t.relname = 'todos' AND c.conname = 'fk_todos_label'
  ) THEN
    -- only add constraint if labels table exists
    IF EXISTS (SELECT 1 FROM pg_class WHERE relname = 'labels') THEN
      ALTER TABLE todos ADD CONSTRAINT fk_todos_label FOREIGN KEY(label_id) REFERENCES labels(id) ON DELETE SET NULL;
    END IF;
  END IF;
END$$;

-- Add index on label_id
CREATE INDEX IF NOT EXISTS idx_todos_label_id ON todos(label_id);

COMMIT;
